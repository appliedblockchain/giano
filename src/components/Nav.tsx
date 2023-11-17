import React from 'react';
import { NavLink } from 'react-router-dom';

export default function Nav() {
  return (
    <nav>
      <NavLink to={'/register'}>Register</NavLink>
      <NavLink to={'/login'}>Login</NavLink>
    </nav>
  );
}
