import { downloadFile } from '../services/fileMethods';

export async function handleGetRequest(
  request: Request,
  env: Env,
  requestUrl: URL,
): Promise<Response> {
  // display web
  if (requestUrl.pathname === '/') {
    return env.ASSETS.fetch(request);
  }

  // download files
  const filePath =
    requestUrl.searchParams.get('file') ||
    decodeURIComponent(requestUrl.pathname.replace(`/${env.PROTECTED.PROXY_KEYWORD}/`, '/'));
  const isProxyRequest = env.PROTECTED.PROXY_KEYWORD
    ? requestUrl.pathname.startsWith(`/${env.PROTECTED.PROXY_KEYWORD}`)
    : false;
  const fileName = filePath.split('/').pop();

  if (!fileName) {
    return new Response('Bad Request', { status: 400 });
  }

  if (fileName.toLowerCase() === env.PROTECTED.PASSWD_FILENAME.toLowerCase()) {
    return new Response('Access Denied', { status: 403 });
  }

  return downloadFile(filePath, isProxyRequest, requestUrl.searchParams.get('format'));
}
