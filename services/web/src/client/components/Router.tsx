import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

const ERC721AccountClient = React.lazy(() => import('./AccountClient'));
const Login = React.lazy(() => import('./Login'));

export default function Router() {
  return (
    <BrowserRouter basename={'/'}>
      <React.Suspense>
        <Routes>
          <Route path={'/'} element={<Navigate to={'/erc721'} />} />
          <Route path={'/login'} element={<Login />} />
          <Route path={'/erc721'} element={<ERC721AccountClient />} />
        </Routes>
      </React.Suspense>
    </BrowserRouter>
  );
}
