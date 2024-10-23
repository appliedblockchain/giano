import { ethers } from 'ethers';
import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Image, SafeAreaView, ScrollView, StatusBar, StyleSheet, Text, View } from 'react-native';

import logo from './assets/logo.png';
import { usePasskey } from './providers/passkey';

import { Btn, Section } from './components';

const faucetDropAmount = ethers.parseEther('100');

const Wallet = () => {
    const { user, coinContract, logout } = usePasskey();
    const [balance, setBalance] = useState<string>(ethers.formatEther(0n));
    const [loading, setLoading] = useState<boolean>(false);
    const getBalance = useCallback(async () => {
        if(user && coinContract && !loading){
            setLoading(true);
            const balance = await coinContract.balanceOf(user.account);
            setBalance(ethers.formatEther(balance));
            setLoading(false);
        }
    }, [user, coinContract]);

    const transferFromFaucet = useCallback(async () => {
        if (user && coinContract && !loading) {
            setLoading(true);
            const tx = await coinContract.transfer(user.account, faucetDropAmount);
            await tx.wait();
            setLoading(false);

            getBalance();
        }
    }, [user, coinContract, loading]);

    useEffect(() => {
        getBalance();
    }, [getBalance]);

    return (
        <SafeAreaView style={{ flex: 1 }}>
            <StatusBar />

            <View style={[styles.hstack, styles.vcenter, styles.between, styles.hm20]}>
                <View style={[styles.hstack, styles.vcenter]}>
                    <Image source={logo} style={{ width: 50, height: 50, marginRight: 10 }} />
                    <Text style={styles.h1}>GIANO</Text>
                </View>
                <View style={{
                    marginLeft: 10,
                    flex: 1,
                    borderRadius: 4,
                    paddingHorizontal: 10,
                    paddingVertical: 10,
                    backgroundColor: '#ddd',
                }}>
                    <Text numberOfLines={1} ellipsizeMode="tail">{user?.account}</Text>
                </View>
            </View>
            <ScrollView
                contentContainerStyle={{ flexGrow: 1 }}>
                <Section title='Balance'>
                    <Text style={[styles.tcenter, styles.h2]}>${balance}</Text>
                </Section>
                <Section title="Mint">
                    <Btn disabled={true} title="Mint" onPress={() => { }} />
                </Section>
                <Section title="Transfer">
                    <Btn disabled={true}  title="Transfer" onPress={() => { }} />
                </Section>
                <Section title="Faucet">
                    <Text style={[styles.tcenter]}>
                        Faucet $100
                    </Text>
                    <View style={[styles.center, { height: 50  }]}>
                    {loading && <ActivityIndicator />}
                    {!loading && <Btn title="Faucet" onPress={transferFromFaucet} />}
                    </View>

                </Section>
                <Section title="Send">
                    <Btn disabled={true} title="Send" onPress={() => { }} />
                </Section>
                <Section title="Logout">
                    <Btn title="Logout" onPress={logout} />
                </Section>
            </ScrollView>
        </SafeAreaView>
    );
}

const styles = StyleSheet.create({
    h1: {
        fontSize: 24,
        fontWeight: 'bold'
    },
    h2: {
        fontSize: 20,
        fontWeight: 'bold'
    },
    h3: {
        fontSize: 18,
        fontWeight: 'bold'
    },
    hm20: {
        marginHorizontal: 20
    },
    vcenter: {
        alignItems: 'center'
    },
    tcenter:{
        textAlign: 'center'
    },
    center: {
        alignItems: 'center',
        justifyContent: 'center'

    },
    between: {
        justifyContent: 'space-between'
    },
    vstack: {
        display: 'flex',
        flexDirection: 'column',
        // gap: 20
    },
    hstack: {
        display: 'flex',
        flexDirection: 'row',
        // gap: 20
    },
    flex: {
        flex: 1
    }
})
export default Wallet;
