import { Buffer } from 'buffer';
import { ethers } from 'ethers';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert } from 'react-native';
import { Passkey } from 'react-native-passkey';

import { credentialClient } from '@giano/client/credential/rm-mobile';
import { extractPublicKey } from '@giano/client/extractPublicKey';
import { uint8ArrayToUint256 } from '@giano/client/misc/uint';
import { Account, Account__factory, AccountFactory__factory, GenericERC20, GenericERC20__factory, GenericERC721, GenericERC721__factory } from '@giano/contracts/typechain-types';

const { getCredential, createCredential } = credentialClient({
    rp: {
        name: 'Giano',
        id: 'deadly-possible-spider.ngrok-free.app',
    },
});

export interface PasskeyContextType {
    openPasskeyCredential: (username: string) => Promise<any>;
    createUser: (username: string) => Promise<any>;
    isSupported: boolean;
    user: User | null;
    logout: () => void;
    tokenContract: GenericERC721 | null;
    coinContract: GenericERC20 | null;
    accountContract?: Account | null;
}

export type User = {
    account: string;
    rawId: Uint8Array;
    credentialId: string;
};

export const PasskeyContext = React.createContext<PasskeyContextType>({
    openPasskeyCredential: async () => { },
    createUser: async () => { },
    isSupported: false,
    user: null,
    logout: () => { },
    tokenContract: null,
    coinContract: null,
    accountContract: null,
});


export const PasskeyProvider = ({ children }: { children: React.ReactNode; }) => {
    const [isSupported, setIsSupported] = useState<boolean>(false);
    const [user, setUser] = useState<User | null>(null);

    const provider = useMemo(() => new ethers.WebSocketProvider('ws://localhost:8545'), []);
    const signer = useMemo(() => new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider), [provider]);
    const accountFactory = useMemo(() => AccountFactory__factory.connect('0x5fbdb2315678afecb367f032d93f642f64180aa3', signer), [signer]);
    const tokenContract = useMemo(() => GenericERC721__factory.connect('0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0', signer), [signer]);
    const coinContract = useMemo(() => GenericERC20__factory.connect('0xe7f1725e7734ce288f8367e1bb143e90bb3f0512', signer), [signer]);
  const accountContract = useMemo(() => (user ? Account__factory.connect(user.account, signer) : undefined), [user?.account, signer]);

    useEffect(() => {
        setIsSupported(Passkey.isSupported());
    }, []);

    const logout = useCallback(() => {
        setUser(null);
    }, []);

    const openPasskeyCredential = useCallback(async () => {
        const credential = await getCredential();
        if (!credential) {
            return;
        }
        console.log('credential')
        console.log(JSON.stringify(credential, null, 2));
        // return;

        const rawId = new TextEncoder().encode(credential.rawId);
        const userId = uint8ArrayToUint256(rawId.slice(-32));

        const user = await accountFactory.getUser(userId);
        if (user.account !== ethers.ZeroAddress) {
            setUser({
                account: user.account,
                rawId,
                credentialId: userId.toString(),
            });
        } else {
            Alert.alert('User not found', 'Please create an account');
        }

        console.log('openPasskeyCredential', rawId, credential, user);
        return credential;
    }, [accountFactory]);

    const createUser = useCallback(async (username: string) => {
        if (!username) {
            Alert.alert('Username', 'Please enter a username');
            return;
        }
        try {
            console.log('createUser', username);
            // giano specific
            const credential = await createCredential(username);
        console.log('createCredential', JSON.stringify(credential, null, 2));
            const { x, y } = await extractPublicKey(
                Buffer.from(credential.response.attestationObject, 'base64')
            );
            console.log('extractPublicKey', x, y);
            // // contract specific
            const rawId = new TextEncoder().encode(credential.rawId);
            console.log('rawId', rawId);
            const userId = uint8ArrayToUint256(rawId.slice(-32));
            console.log('userId', userId);
            await (await accountFactory.createUser(userId, { x, y })).wait();

            const user = await accountFactory.getUser(userId);

            if (user.account !== ethers.ZeroAddress) {
                setUser({
                    account: user.account,
                    rawId,
                    credentialId: userId.toString(),
                });
            } else {
                Alert.alert('User not found', 'Please try again');
            }
            console.log('createUser', credential);
            return credential;
        } catch (error) {
            console.error(error);
            Alert.alert('Error', 'Something went wrong. Please check the console');
        }
    }, [accountFactory]);

    return (
        <PasskeyContext.Provider value={{
            openPasskeyCredential,
            createUser,
            isSupported,
            user,
            logout,
            tokenContract,
            coinContract,
            accountContract,
        }}>
            {children}
        </PasskeyContext.Provider>
    );
};


export const usePasskey = () => {
    const context = React.useContext(PasskeyContext);
    if (!context) {
        throw new Error('usePasskey must be used within a PasskeyContext');
    }
    return context;
};


