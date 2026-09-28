import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

/** The page's tabs. The hash mirrors the active tab so a link like `#transactions` still works. */
export const TABS = [
  { id: 'home', label: 'Home' },
  { id: 'setup', label: 'Setup' },
  { id: 'wallet', label: 'Wallet' },
  { id: 'transactions', label: 'Transactions' },
  { id: 'tokens', label: 'Tokens' },
  { id: 'advanced', label: 'Advanced' },
  { id: 'failure-lab', label: 'Failure lab' },
  { id: 'ledger', label: 'Ledger' },
] as const;

export type TabId = (typeof TABS)[number]['id'];

const isTab = (value: string): value is TabId => TABS.some((tab) => tab.id === value);

type TabNav = { tab: TabId; go: (tab: TabId) => void };

const TabNavContext = createContext<TabNav | null>(null);

export function TabNavProvider({ children }: { children: ReactNode }) {
  const [tab, setTab] = useState<TabId>(() => {
    const fromHash = typeof window !== 'undefined' ? window.location.hash.replace(/^#/, '') : '';
    return isTab(fromHash) ? fromHash : 'home';
  });
  const go = useCallback((next: TabId) => {
    setTab(next);
    if (typeof window !== 'undefined') window.history.replaceState(null, '', `#${next}`);
  }, []);
  useEffect(() => {
    const onHash = () => {
      const fromHash = window.location.hash.replace(/^#/, '');
      if (isTab(fromHash)) setTab(fromHash);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const value = useMemo(() => ({ tab, go }), [tab, go]);
  return <TabNavContext.Provider value={value}>{children}</TabNavContext.Provider>;
}

export function useTabNav(): TabNav {
  const nav = useContext(TabNavContext);
  if (!nav) throw new Error('useTabNav must be used inside TabNavProvider');
  return nav;
}
