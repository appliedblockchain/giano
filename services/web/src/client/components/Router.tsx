import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

const ERC721AccountClient = React.lazy(() => import('./ERC721AccountClient'));

export default function Router() {
  return (
    <BrowserRouter basename={'/'}>
      <React.Suspense>
        <Routes>
          <Route path={'/'} element={<Navigate to={'/erc721'} />} />
          <Route path={'/erc721'} element={<ERC721AccountClient />} />
        </Routes>
      </React.Suspense>
    </BrowserRouter>
  );
}
