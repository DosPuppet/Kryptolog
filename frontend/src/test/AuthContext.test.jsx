import { describe, it, expect } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { AuthProvider, useAuth } from '../context/AuthContext';

// Helper component to expose auth context for testing
function AuthConsumer() {
    const { user, token, isAuthenticated, authType, login, logout, updateUser } = useAuth();
    return (
        <div>
            <span data-testid="is-auth">{String(isAuthenticated)}</span>
            <span data-testid="username">{user?.username ?? 'none'}</span>
            <span data-testid="auth-type">{authType ?? 'none'}</span>
            <span data-testid="token">{token ?? 'none'}</span>
            <button data-testid="login-btn" onClick={() =>
                login({ username: 'Alice', address: '0xabc' }, 'trustkeys', 'test_token')
            }>Login</button>
            <button data-testid="logout-btn" onClick={() => logout()}>Logout</button>
            <button data-testid="update-btn" onClick={() =>
                updateUser({ username: 'Bob', address: '0xabc' })
            }>Update</button>
        </div>
    );
}

describe('AuthContext', () => {
    it('starts unauthenticated', () => {
        render(<AuthProvider><AuthConsumer /></AuthProvider>);
        expect(screen.getByTestId('is-auth').textContent).toBe('false');
        expect(screen.getByTestId('username').textContent).toBe('none');
        expect(screen.getByTestId('auth-type').textContent).toBe('none');
        expect(screen.getByTestId('token').textContent).toBe('none');
    });

    it('login sets user, token, authType, and isAuthenticated', () => {
        render(<AuthProvider><AuthConsumer /></AuthProvider>);
        act(() => {
            screen.getByTestId('login-btn').click();
        });
        expect(screen.getByTestId('is-auth').textContent).toBe('true');
        expect(screen.getByTestId('username').textContent).toBe('Alice');
        expect(screen.getByTestId('auth-type').textContent).toBe('trustkeys');
        expect(screen.getByTestId('token').textContent).toBe('test_token');
    });

    it('logout clears everything', () => {
        render(<AuthProvider><AuthConsumer /></AuthProvider>);
        act(() => screen.getByTestId('login-btn').click());
        expect(screen.getByTestId('is-auth').textContent).toBe('true');

        act(() => screen.getByTestId('logout-btn').click());
        expect(screen.getByTestId('is-auth').textContent).toBe('false');
        expect(screen.getByTestId('username').textContent).toBe('none');
        expect(screen.getByTestId('token').textContent).toBe('none');
    });

    it('updateUser modifies user without affecting auth state', () => {
        render(<AuthProvider><AuthConsumer /></AuthProvider>);
        act(() => screen.getByTestId('login-btn').click());
        expect(screen.getByTestId('username').textContent).toBe('Alice');

        act(() => screen.getByTestId('update-btn').click());
        expect(screen.getByTestId('username').textContent).toBe('Bob');
        expect(screen.getByTestId('is-auth').textContent).toBe('true');
        expect(screen.getByTestId('token').textContent).toBe('test_token');
    });

    it('throws error when useAuth is used outside AuthProvider', () => {
        // Suppress console.error for this test
        const spy = vi.spyOn(console, 'error').mockImplementation(() => { });
        expect(() => render(<AuthConsumer />)).toThrow(
            'useAuth must be used within an AuthProvider'
        );
        spy.mockRestore();
    });
});
