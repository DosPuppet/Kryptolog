const fs = require('fs');
const path = require('path');

const files = [
    'node_modules/crystals-kyber/kyber512.js',
    'node_modules/crystals-kyber/kyber768.js',
    'node_modules/crystals-kyber/kyber1024.js'
];

files.forEach(file => {
    const filePath = path.join(__dirname, '..', file);
    if (!fs.existsSync(filePath)) {
        console.warn(`File not found: ${filePath}`);
        return;
    }

    console.log(`Patching ${file}...`);
    let content = fs.readFileSync(filePath, 'utf8');

    // 1. Fix implicit globals (KeyGen512 =, Encrypt512 =, etc.)
    // We match the specific function names for each file type
    if (file.includes('kyber512')) {
        content = content.replace(/^KeyGen512 = function/m, 'const KeyGen512 = function');
        content = content.replace(/^Encrypt512 = function/m, 'const Encrypt512 = function');
        content = content.replace(/^Decrypt512 = function/m, 'const Decrypt512 = function');
        content = content.replace(/^Test512 = function/m, 'const Test512 = function');
    } else if (file.includes('kyber768')) {
        content = content.replace(/^KeyGen768 = function/m, 'const KeyGen768 = function');
        content = content.replace(/^Encrypt768 = function/m, 'const Encrypt768 = function');
        content = content.replace(/^Decrypt768 = function/m, 'const Decrypt768 = function');
        content = content.replace(/^Test768 = function/m, 'const Test768 = function');
    } else if (file.includes('kyber1024')) {
        content = content.replace(/^KeyGen1024 = function/m, 'const KeyGen1024 = function');
        content = content.replace(/^Encrypt1024 = function/m, 'const Encrypt1024 = function');
        content = content.replace(/^Decrypt1024 = function/m, 'const Decrypt1024 = function');
        content = content.replace(/^Test1024 = function/m, 'const Test1024 = function');
    }

    // 2. Fix crypto import
    // Replace: const webcrypto = require('crypto').webcrypto;
    // With: const webcrypto = (typeof globalThis !== 'undefined' && globalThis.crypto) ? globalThis.crypto : require('crypto').webcrypto;
    const cryptoPatch = "const webcrypto = (typeof globalThis !== 'undefined' && globalThis.crypto) ? globalThis.crypto : require('crypto').webcrypto;";
    content = content.replace(/const webcrypto = require\('crypto'\)\.webcrypto;/g, cryptoPatch);
    // Also handle the case where it might not have 'const' (older versions?) or if I already patched it manually and it's slightly different? 
    // The original code was: const webcrypto = require('crypto').webcrypto;

    // 3. Fix undeclared loop variable 'i'
    // Replace: for (i = 0; i < paramsK; i++) {
    // With: for (let i = 0; i < paramsK; i++) {
    content = content.replace(/for \(i = 0; i < paramsK; i\+\+\) \{/g, 'for (let i = 0; i < paramsK; i++) {');

    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`Patched ${file}`);
});
