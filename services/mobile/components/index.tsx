import { PropsWithChildren } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";


export const Btn = (props: any) => {
    return <Pressable onPress={props.onPress} style={[styles.button, props.style]}>
        <Text style={styles.buttonText}>{props.title}</Text>
    </Pressable>;
};

export const Divider = ({ children }: { children: string }) => {
    return (<View style={{ flexDirection: 'row', alignItems: 'center' }}>
        <View style={{ flex: 1, height: 1, backgroundColor: '#ccc' }} />
        <View>
            <Text style={{ paddingHorizontal: 12, textAlign: 'center' }}>{children}</Text>
        </View>
        <View style={{ flex: 1, height: 1, backgroundColor: '#ccc' }} />
    </View>);
};


type SectionProps = PropsWithChildren<{
    title?: string;
}>;

export function Section({ children, title }: SectionProps): React.JSX.Element {
    return (
        <View style={styles.sectionContainer}>
            <Text
                style={[
                    styles.sectionTitle,
                ]}>
                {title}
            </Text>
            {children}
        </View>
    );
}


const styles = StyleSheet.create({
    sectionContainer: {
        marginTop: 32,
        paddingHorizontal: 24,
        gap: 10,
    },
    sectionTitle: {
        fontSize: 24,
        fontWeight: '600',
    },
    button: {
        backgroundColor: 'rgba(111, 89, 240, 1)',
        borderRadius: 8,
        padding: 10,
        justifyContent: 'center',
        alignItems: 'center',
        width: '100%',
    },
    buttonText: {
        color: 'white',
        fontSize: 14,
        fontWeight: 'bold',
        textTransform: 'uppercase',
    },
});
