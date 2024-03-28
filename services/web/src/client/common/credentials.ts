export const getCredential = async (id?: BufferSource, challenge?: BufferSource) => {
  const params = {
    challenge: challenge || new TextEncoder().encode('abc'),
    rpId: window.location.hostname,
    userVerification: 'preferred',
    ...(id && {
      allowCredentials: [
        {
          id: id,
          type: 'public-key',
        },
      ],
    }),
  };
  console.log({ params });
  return (await window.navigator.credentials.get({
    publicKey: params,
  })) as PublicKeyCredential & { response: AuthenticatorAssertionResponse };
};
