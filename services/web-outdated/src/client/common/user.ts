export type User = {
  account: string;
  rawId: Uint8Array;
  credentialId: string;
};

export const setSessionUser = (user: User | null) => {
  sessionStorage.setItem(
    'user',
    JSON.stringify(user, (k, v) => {
      if (k === 'rawId') {
        return Array.from(v);
      }
      return v;
    }),
  );
};

export const getSessionUser = (): User | null => {
  const userJson = sessionStorage.getItem('user');
  return userJson
    ? JSON.parse(userJson, (k, v) => {
        if (k === 'rawId') {
          return new Uint8Array(v);
        }
        return v;
      })
    : null;
};
