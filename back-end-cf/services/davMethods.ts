import type { DriveItem, DriveItemCollection } from '../types/apiType';
import { runtimeEnv } from '../types/env';
import { fetchWithAuth, fetchBatchRes } from './fetchUtils';
import { getAndSaveSkipToken } from './utils';
import { createReturnXml, createPropfindXml } from './davUtils';
import { parsePath, buildUriPath } from './pathUtils';

export const davClient = {
  handlePropfind,
  handleCopyMove,
  handleDelete,
  handleHead,
  handleMkcol,
  handlePut,
};

async function handlePropfind(filePath: string) {
  const { path, parent } = parsePath(filePath);
  const allFiles: DriveItem[] = [];
  const skipTokens: string[] = [];

  const currentTokens = await getAndSaveSkipToken(path);
  const itemPathWrapped = buildUriPath(path, runtimeEnv.PROTECTED.EXPOSE_PATH, '');
  const select = '?select=name,size,lastModifiedDateTime,file';
  const baseUrl = `/me/drive/root${itemPathWrapped}/children${select}&top=1000`;

  const createListRequest = (id: string, skipToken?: string) => ({
    id,
    method: 'GET',
    url: skipToken ? `${baseUrl}&skipToken=${skipToken}` : baseUrl,
    headers: { 'Content-Type': 'application/json' },
    body: {},
  });

  const batchRequest = {
    requests: [
      {
        id: '1',
        method: 'GET',
        url: `/me/drive/root${itemPathWrapped}${select}`,
        headers: { 'Content-Type': 'application/json' },
        body: {},
      },
      createListRequest('2'),
      ...currentTokens.map((token, index) => createListRequest(`${index + 3}`, token)),
    ],
  };

  const batchResult = await fetchBatchRes(batchRequest);
  batchResult.responses.sort((a, b) => parseInt(a.id) - parseInt(b.id));

  for (const resp of batchResult.responses) {
    if (resp.status !== 200) {
      return {
        davXml: createReturnXml(filePath, resp.status, 'Failed to fetch files'),
        davStatus: resp.status,
      };
    }

    if (resp.id === '1') {
      const item = resp.body as DriveItem;
      allFiles.push({
        ...item,
        name: item.file ? item.name : '',
      });
      continue;
    }

    const items = (resp.body as DriveItemCollection).value;
    allFiles.push(...items);

    const nextLink = (resp.body as DriveItemCollection)['@odata.nextLink'];
    const skipToken = nextLink
      ? (new URL(nextLink).searchParams.get('$skiptoken') ?? undefined)
      : undefined;
    if (skipToken) {
      skipTokens.push(skipToken);
    }
  }

  await getAndSaveSkipToken(path, skipTokens);

  const propfindPath = allFiles[0]?.file ? parent : path;
  const responseXML = createPropfindXml(propfindPath, allFiles);
  return { davXml: responseXML, davStatus: 207 };
}

async function handleCopyMove(filePath: string, method: 'COPY' | 'MOVE', destination: string) {
  const { parent: newParent, tail: newTail } = parsePath(destination);
  const uri =
    buildUriPath(filePath, runtimeEnv.PROTECTED.EXPOSE_PATH, runtimeEnv.OAUTH.apiUrl) +
    (method === 'COPY' ? '/copy' : '');

  const resp = await fetchWithAuth(uri, {
    method: method === 'COPY' ? 'POST' : 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: newTail,
      parentReference: {
        path: `/drive/root:${runtimeEnv.PROTECTED.EXPOSE_PATH}${newParent}`,
      },
    }),
  });

  const davStatus = resp.status === 200 ? 201 : resp.status;
  const responseXML =
    davStatus === 201 ? null : createReturnXml(filePath, davStatus, resp.statusText);

  return { davXml: responseXML, davStatus: davStatus };
}

async function handleDelete(filePath: string) {
  const uri = buildUriPath(filePath, runtimeEnv.PROTECTED.EXPOSE_PATH, runtimeEnv.OAUTH.apiUrl);
  const res = await fetchWithAuth(uri, { method: 'DELETE' });
  const davStatus = res.status;
  const responseXML =
    davStatus === 204 ? null : createReturnXml(filePath, davStatus, res.statusText);

  return { davXml: responseXML, davStatus: davStatus };
}

async function handleHead(filePath: string) {
  const uri = [
    buildUriPath(filePath, runtimeEnv.PROTECTED.EXPOSE_PATH, runtimeEnv.OAUTH.apiUrl),
    '?select=size,file,folder,lastModifiedDateTime',
  ].join('');
  const resp = await fetchWithAuth(uri);
  const data: DriveItem = await resp.json();

  return {
    davXml: null,
    davStatus: data?.folder ? 403 : resp.status,
    davHeaders: data?.file
      ? {
          'Content-Length': data.size.toString(),
          'Content-Type': data.file.mimeType,
          'Last-Modified': new Date(data.lastModifiedDateTime).toUTCString(),
        }
      : {},
  };
}

async function handleMkcol(filePath: string) {
  const { parent, tail } = parsePath(filePath);
  const uri =
    buildUriPath(parent, runtimeEnv.PROTECTED.EXPOSE_PATH, runtimeEnv.OAUTH.apiUrl) + '/children';

  const res = await fetchWithAuth(uri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: tail,
      folder: {},
      '@microsoft.graph.conflictBehavior': 'replace',
    }),
  });

  const davStatus = res.status === 200 ? 201 : res.status;
  const responseXML =
    davStatus === 201 ? null : createReturnXml(filePath, davStatus, res.statusText);

  return { davXml: responseXML, davStatus: davStatus };
}

async function handlePut(filePath: string, request: Request) {
  const simpleUploadLimit = 4 * 1024 * 1024; // 4MB
  const chunkSize = 60 * 1024 * 1024;
  const contentLength = request.headers.get('Content-Length') || '0';
  const fileSize = parseInt(contentLength);
  const fileBuffer = await request.arrayBuffer();

  if (fileSize <= simpleUploadLimit) {
    const uri =
      buildUriPath(filePath, runtimeEnv.PROTECTED.EXPOSE_PATH, runtimeEnv.OAUTH.apiUrl) +
      '/content';
    const res = await fetchWithAuth(uri, {
      method: 'PUT',
      body: fileBuffer,
    });

    return { davXml: null, davStatus: res.status === 200 ? 204 : res.status };
  }

  if (fileSize > chunkSize) {
    return {
      davXml: createReturnXml(filePath, 413, 'Request Entity Too Large'),
      davStatus: 413,
    };
  }

  const uri =
    buildUriPath(filePath, runtimeEnv.PROTECTED.EXPOSE_PATH, runtimeEnv.OAUTH.apiUrl) +
    '/createUploadSession';
  const uploadSessionRes = await fetchWithAuth(uri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      item: { '@microsoft.graph.conflictBehavior': 'replace' },
    }),
  });

  const { uploadUrl } = (await uploadSessionRes.json()) as { uploadUrl: string };
  const res = await fetch(uploadUrl, {
    method: 'PUT',
    body: fileBuffer,
    headers: {
      'Content-Length': contentLength,
      'Content-Range': `bytes 0-${fileSize - 1}/${fileSize}`,
    },
  });

  return { davXml: null, davStatus: res.status === 200 ? 204 : res.status };
}
