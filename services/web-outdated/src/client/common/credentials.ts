export const getCredential = async (id?: BufferSource, challenge?: BufferSource) => {
  const params: PublicKeyCredentialRequestOptions = {
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
  return (await window.navigator.credentials.get({
    publicKey: params,
  })) as PublicKeyCredential & { response: AuthenticatorAssertionResponse };
};
