import type { PostPayload, Resource } from '../types/apiType';
import { authenticatePost, getTokenScopes } from '../services/authUtils';
import { downloadFile, fetchFiles, fetchUploadLinks } from '../services/fileMethods';
import { saveDeployData } from '../services/deployMethods';

export async function handlePostRequest(
  request: Request,
  env: Env,
  requestUrl: URL,
): Promise<Response> {
  // save deploy data
  if (requestUrl.pathname === '/deployreturn') {
    const codeUrlEntry = (await request.formData()).get('codeUrl');
    const codeUrl: string = typeof codeUrlEntry === 'string' ? codeUrlEntry : '';
    return saveDeployData(env, requestUrl, codeUrl);
  }

  const returnHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'max-age=3600',
    'Content-Type': 'application/json; charset=utf-8',
  };
  const body: PostPayload = await request.json();
  const requestPath = body.path || '/';
  const tokenScopeList = await getTokenScopes(env.PASSWORD, requestUrl, requestPath);
  const isAuthorized = await authenticatePost(requestPath, body.passwd, env.PASSWORD);

  // Upload files
  if (requestUrl.searchParams.has('upload')) {
    if (!body.files || body.files.length === 0) {
      return new Response('no files to upload', { status: 400 });
    }

    const isUploadFileExists =
      tokenScopeList.includes('upload') ||
      (await downloadFile(`${requestPath}/.upload`)).status === 302;
    const isUploadAllowed = tokenScopeList.includes('upload') || isAuthorized;

    if (
      !isUploadFileExists ||
      !isUploadAllowed ||
      body.files?.some(
        (file) =>
          (file.remotePath.split('/').pop() ?? '').toLowerCase() ===
          env.PROTECTED.PASSWD_FILENAME.toLowerCase(),
      )
    ) {
      return new Response('access denied', { status: 403 });
    }

    const uploadLinks = JSON.stringify(await fetchUploadLinks(body.files));
    return new Response(uploadLinks, {
      headers: returnHeaders,
    });
  }

  // List a folder
  const isListAllowed = tokenScopeList.includes('list') || isAuthorized;
  const filesRes = isListAllowed
    ? await fetchFiles(requestPath, body.skipToken, body.orderby)
    : {
        parent: requestPath,
        files: [],
        encrypted: true,
      };

  if (tokenScopeList.includes('upload')) {
    (filesRes.files as Resource[]).unshift({
      name: '.upload',
      size: 0,
      lastModifiedDateTime: new Date().toISOString(),
      url: `upload`,
    });
  }

  return new Response(JSON.stringify(filesRes), {
    headers: returnHeaders,
  });
}
