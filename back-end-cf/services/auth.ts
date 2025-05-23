import { PROTECTED } from '../types/apiType';
import { sha256 } from './utils';
import { downloadFile } from '../handlers/file-handler';

export async function authenticate(
  path: string,
  passwd?: string,
  davCredentials?: string,
): Promise<boolean> {
  try {
    const [hashedPasswd, hashedDav] = await Promise.all([
      sha256(passwd || ''),
      sha256(davCredentials?.split(':')[1] || ''),
    ]);

    if (davCredentials && hashedPasswd === hashedDav) {
      return true;
    }

    const pathsToTry = [path];
    if (path !== '/' && path.split('/').length <= PROTECTED.PROTECTED_LAYERS) {
      pathsToTry.push('/');
    }
    const downloads = await Promise.all(
      pathsToTry.map((p) =>
        downloadFile(`${p}/${PROTECTED.PASSWD_FILENAME}`, true).then((resp) =>
          resp.status === 404 ? undefined : resp.text(),
        ),
      ),
    );

    for (const pwFileContent of downloads) {
      if (pwFileContent && hashedPasswd === pwFileContent) {
        return true;
      }
    }
    return downloads.every((content) => content === undefined);
  } catch (e) {
    return false;
  }
}

export function authenticateWebdav(
  davAuthHeader: string | null,
  davCredentials: string | undefined,
): boolean {
  if (!davAuthHeader || !davCredentials) {
    return false;
  }

  const encoder = new TextEncoder();
  const header = encoder.encode(davAuthHeader);
  const expected = encoder.encode(`Basic ${btoa(davCredentials)}`);
  return (
    // @ts-ignore
    header.byteLength === expected.byteLength && crypto.subtle.timingSafeEqual(header, expected)
  );
}
