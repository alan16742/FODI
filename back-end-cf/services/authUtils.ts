import { runtimeEnv } from '../types/env';
import { sha256, secureEqual } from './utils';
import { downloadFile } from './fileMethods';
import type { TokenScope } from '../types/apiType';

export async function authenticatePost(
  path: string,
  passwd?: string,
  envPasswd?: string,
): Promise<boolean> {
  // empty input password, improve loading speed
  if (!passwd && path.split('/').length <= runtimeEnv.PROTECTED.PROTECTED_LAYERS) {
    return false;
  }

  // check env password
  if (envPasswd && secureEqual(passwd, envPasswd)) {
    return true;
  }

  // check password files in onedrive
  const hashedPasswd = await sha256(passwd || '');
  const pathsToTry = [path === '/' ? '' : path];
  if (path !== '/' && path.split('/').length <= runtimeEnv.PROTECTED.PROTECTED_LAYERS) {
    pathsToTry.push('');
  }
  const downloads = await Promise.all(
    pathsToTry.map((p) =>
      downloadFile(`${p}/${runtimeEnv.PROTECTED.PASSWD_FILENAME}`, true).then((resp) =>
        resp.status === 404 ? undefined : resp.text(),
      ),
    ),
  );

  for (const pwFileContent of downloads) {
    if (pwFileContent && secureEqual(hashedPasswd, pwFileContent.toLowerCase())) {
      return true;
    }
  }
  return downloads.every((content) => content === undefined);
}

export function authenticateWebdav(
  davAuthHeader: string | null,
  USERNAME: string | undefined,
  PASSWORD: string | undefined,
): boolean {
  if (!davAuthHeader || !USERNAME || !PASSWORD) {
    return false;
  }

  return secureEqual(davAuthHeader, `Basic ${btoa(`${USERNAME}:${PASSWORD}`)}`);
}

/**
 * @param envPasswd The environment password used to generate and validate the token.
 * @param url The URL object containing the token and related query parameters.
 * @param postPath Optional. The path of the resource for POST requests; if not provided, the URL pathname is used.
 * @returns Returns a Promise that resolves to an array of tokenScopeList if the token is valid and authorized, otherwise an empty array.
 */
export async function getTokenScopes(
  envPasswd: string | undefined,
  url: URL,
  postPath?: string,
): Promise<TokenScope[]> {
  const tokenScopeList = (url.searchParams.get('ts') || 'download').split(',') as TokenScope[];
  const token = url.searchParams.get('token')?.toLowerCase();
  if (!token || !envPasswd) {
    return [];
  }

  const expires = url.searchParams.get('te');
  if (expires) {
    const now = Math.floor(Date.now() / 1000);
    const exp = parseInt(expires);
    if (isNaN(exp) || now > exp) {
      return [];
    }
  }

  const tokenArgString = [tokenScopeList.join(','), expires].filter(Boolean).join(',');
  const path = postPath || url.pathname;
  const pathSign = await sha256([envPasswd, path, tokenArgString].join(','));

  if (tokenScopeList.length === 1 && tokenScopeList[0] === 'download') {
    const parent = path.split('/').slice(0, -1).join('/') || '/';
    const parentSign = await sha256([envPasswd, parent, tokenArgString].join(','));
    return token === pathSign || token === parentSign ? tokenScopeList : [];
  }

  return token === pathSign ? tokenScopeList : [];
}
