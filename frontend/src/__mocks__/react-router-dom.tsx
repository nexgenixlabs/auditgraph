import React from 'react';

export const Link = ({ children, to, ...rest }: any) => <a href={to} {...rest}>{children}</a>;
export const useNavigate = () => jest.fn();
export const useLocation = () => ({ pathname: '/', search: '', hash: '', state: null });
export const useParams = () => ({});
export const BrowserRouter = ({ children }: any) => <>{children}</>;
export const Routes = ({ children }: any) => <>{children}</>;
export const Route = () => null;
