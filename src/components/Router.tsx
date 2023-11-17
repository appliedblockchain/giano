import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

const Register = React.lazy(() => import('./Register'));
const Login = React.lazy(() => import('./Login'));
const Home = React.lazy(() => import('./Home'));

export default function Router() {
  return (
    <BrowserRouter basename={'/'}>
      <React.Suspense>
        <Routes>
          <Route path={'/'} element={<Navigate to={'/register'} />} />
          <Route path={'/register'} element={<Register />} />
          <Route path={'/login'} element={<Login />} />
          <Route path={'/home'} element={<Home />} />
        </Routes>
      </React.Suspense>
    </BrowserRouter>
  );
}
