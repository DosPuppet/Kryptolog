// The critical path of E2E-RECIPE.md, automated: both custody modes sign in
// against one real server, find each other in the directory, and exchange
// end-to-end encrypted messages both ways.
import { test, expect, autoApprove, PASSWORD } from './fixtures.js';

const shot = (page, name) =>
    page.screenshot({ path: `test-results/shots/${name}.png`, fullPage: true });

test('two people, two custody modes, one conversation', async ({ alice, bob }) => {
    await test.step('Alice: a TrustKeys vault and an identity in it', async () => {
        const popup = await alice.context.newPage();
        await popup.goto(`chrome-extension://${alice.extensionId}/index.html`);
        await popup.getByPlaceholder('Password', { exact: true }).fill(PASSWORD);
        await popup.getByPlaceholder('Confirm Password').fill(PASSWORD);
        await popup.getByRole('button', { name: 'Create Vault' }).click();
        await popup.getByPlaceholder('New Account Name').fill('Alice');
        await popup.locator('.create-account button').click();
        await expect(popup.locator('.account-item')).toHaveCount(1);
        await popup.close();
    });

    await test.step('Alice signs in through the extension', async () => {
        autoApprove(alice.context, alice.extensionId, alice.approvals);
        await alice.page.goto('/');
        await alice.page.getByRole('button', { name: /Connect with TrustKeys/ }).click();
        await expect(alice.page.getByText('Active Secrets')).toBeVisible();

        // What the windows SAID matters as much as that they opened (K-03): the
        // sign-in names this origin, not a raw body.
        expect(alice.approvals[0]).toContain('wants to connect');
        expect(alice.approvals.some((t) => t.includes('Sign in to Kryptolog at http://localhost:5174'))).toBe(true);
    });

    // A local vault asks for its password on every custody call by default
    // (key-cache TTL 0): answer it whenever it appears, the way a person would.
    // Counted, so the run can say how often Bob was asked.
    let bobPrompts = 0;
    await bob.page.addLocatorHandler(bob.page.getByText('Local Vault Security'), async () => {
        bobPrompts += 1;
        await bob.page.getByPlaceholder('Enter Password').fill(PASSWORD);
        await bob.page.getByRole('button', { name: 'Confirm' }).click();
    });

    await test.step('Bob creates a local vault and signs in with it', async () => {
        await bob.page.goto('/');
        await bob.page.getByRole('button', { name: /Create Local Vault/ }).click();
        await bob.page.getByPlaceholder('e.g. Main Account').fill('Bobby');
        await bob.page.getByPlaceholder('Enter secure password').fill(PASSWORD);
        await shot(bob.page, 'bob-vault-form');
        await bob.page.getByRole('button', { name: /Create & Connect/ }).click();
        await expect(bob.page.getByText('Active Secrets')).toBeVisible({ timeout: 60_000 });
    });

    const openMessenger = async (page) => {
        // A link click, never page.goto: the session lives in memory only, and
        // a reload would sign the user out.
        await page.getByRole('link', { name: /Messenger/ }).click();
    };
    const send = async (page, text) => {
        await page.getByPlaceholder('Type a secure message...').fill(text);
        await page.getByPlaceholder('Type a secure message...').press('Enter');
        // Sent means on the sender's own screen — and waiting here is also what
        // lets a vault prompt raised by the send be answered on this page.
        await expect(page.getByText(text)).toBeVisible();
    };

    await test.step('Alice finds Bob in the directory and writes to him', async () => {
        await openMessenger(alice.page);
        await alice.page.getByTitle('New Chat').click();
        await alice.page.getByPlaceholder('Search by username or address...').fill('Bobby');
        await alice.page.getByRole('button', { name: /Bobby/ }).click();
        await send(alice.page, 'Hello Bob, this is post-quantum.');
        await shot(alice.page, 'alice-sent');
    });

    await test.step('Bob reads it, decrypted and verified, and replies', async () => {
        await openMessenger(bob.page);
        await bob.page.getByText('Alice').first().click();
        await shot(bob.page, 'bob-conversation');
        await expect(bob.page.getByText('Hello Bob, this is post-quantum.')).toBeVisible();
        // Verified against the identity key Alice's address names, embedded in
        // the history the server served (crypto-core 3.3.0) — and signed by
        // the extension, the other custody mode from Bob's own.
        await expect(bob.page.getByTitle('Signature verified')).toBeVisible();
        await send(bob.page, 'Received, Alice.');
    });

    await test.step('Alice reads the reply as it arrives, after approving the decryption', async () => {
        // It arrives live (the WebSocket), under a session Bob minted, whose key
        // only Alice's extension can unwrap — and TrustKeys asks before it
        // decrypts, rather than opening a window per incoming message.
        await alice.page.getByRole('button', { name: /Click to Decrypt/ }).click();
        await expect(alice.page.getByText('Received, Alice.')).toBeVisible();
        // A live frame carries Bob's address only, so this one is verified
        // with the key looked up for it — and signed by a local vault.
        await expect(alice.page.getByTitle('Signature verified')).toBeVisible();
        expect(alice.approvals.at(-1)).toContain('Decrypt');
        await shot(alice.page, 'alice-reply');
    });

    const SECRET = 'The vault code is 4711-0815.';

    await test.step('Alice stores a secret and shares it with Bob', async () => {
        await alice.page.getByRole('link', { name: 'Secrets' }).click();
        await alice.page.getByRole('button', { name: /New Secret/ }).click();
        await alice.page.getByPlaceholder('e.g. My WiFi Password').fill('Vault code');
        await alice.page.getByPlaceholder('Enter the secret content here...').fill(SECRET);
        await alice.page.getByRole('button', { name: 'Create Secret' }).click();
        await alice.page.getByTitle('Share').first().click();
        await alice.page.getByPlaceholder('Search by username or address...').fill('Bobby');
        await alice.page.getByRole('button', { name: /Bobby/ }).click();
        await alice.page.getByRole('button', { name: 'Share with Bobby' }).click();
        await expect(alice.page.getByText(/shared/i).first()).toBeVisible();
        await shot(alice.page, 'alice-shared');
    });

    await test.step('Bob opens it', async () => {
        await bob.page.getByRole('link', { name: 'Secrets' }).click();
        await bob.page.getByText('Shared with me').click();
        await shot(bob.page, 'bob-shared-list');
        await bob.page.getByText('Click to Decrypt').first().click();
        await expect(bob.page.getByText(SECRET)).toBeVisible();
        await shot(bob.page, 'bob-secret');
    });

    // ── Replacing an encryption key (crypto-core 5.1.0) ──
    // Bob rotates; what he holds moves to the new key, his history stays
    // readable with the retired one, and Alice — who has his old key pinned
    // and a session wrapped to it — is stopped, told it was a rotation, and
    // writes again only once she confirms.
    const AFTER = 'Written after the rotation.';

    await test.step('Bob replaces his encryption key', async () => {
        await bob.page.getByRole('button', { name: /Bobby/ }).first().click();
        const section = bob.page.getByTestId('encryption-key-section');
        const before = await section.getByTestId('current-kid').innerText();
        await section.getByRole('button', { name: 'Replace my encryption key' }).click();
        await bob.page.getByRole('button', { name: 'Replace the key' }).click();
        // The grant on Alice's secret is the one key Bob holds: moved to the new key.
        await expect(bob.page.getByText(/Encryption key replaced\. 1 key\(s\) moved to it\./)).toBeVisible({ timeout: 60_000 });
        await expect(section.getByTestId('current-kid')).not.toHaveText(before);
        await expect(section.getByTestId('retired-key')).toHaveCount(1);
        await shot(bob.page, 'bob-rotated');
        await bob.page.getByRole('button', { name: 'Close' }).click();
    });

    await test.step('Bob signs in again and opens the shared secret, now sealed to his new key', async () => {
        // A fresh session, not the open page: the card still shows the plaintext
        // from before, and the list still holds the old wrap with its file key
        // cached. Signing in again reopens the vault as it was SAVED and fetches
        // the grant as the server now holds it — re-wrapped to the new key.
        await bob.page.getByTitle('Logout').click();
        await bob.page.getByRole('button', { name: /Unlock Local Vault/ }).click();
        await bob.page.getByPlaceholder('Enter secure password').fill(PASSWORD);
        await bob.page.getByRole('button', { name: /Unlock & Connect/ }).click();
        await expect(bob.page.getByText('Active Secrets')).toBeVisible({ timeout: 60_000 });
        await expect(bob.page.getByText('Shared with me')).toBeVisible();
        await bob.page.getByText('Click to Decrypt').first().click();
        await expect(bob.page.getByText(SECRET)).toBeVisible();
    });

    await test.step('Alice is stopped, told it was a rotation, confirms, and writes again', async () => {
        await openMessenger(alice.page);
        await alice.page.getByText('Bobby').first().click();
        await expect(alice.page.getByTestId('key-rotated')).toBeVisible();
        await expect(alice.page.getByTestId('key-changed')).toContainText('replaced their encryption key');
        await shot(alice.page, 'alice-rotation-banner');
        await alice.page.getByRole('button', { name: /I verified it/ }).click();
        await send(alice.page, AFTER);
    });

    await test.step('Bob reads it under his new key, and his history under the retired one', async () => {
        await openMessenger(bob.page);
        await bob.page.getByText('Alice').first().click();
        await expect(bob.page.getByText(AFTER)).toBeVisible();
        await expect(bob.page.getByText('Hello Bob, this is post-quantum.')).toBeVisible();
        await shot(bob.page, 'bob-after-rotation');
        test.info().annotations.push({ type: 'bob vault prompts', description: String(bobPrompts) });
    });
});
