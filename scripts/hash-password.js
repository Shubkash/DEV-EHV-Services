import crypto from 'crypto';

const password = process.argv[2];
if (!password || password.length < 12) {
  console.error('Provide a password of at least 12 characters. Example: npm run hash-password -- "your-password"');
  process.exit(1);
}

const salt = crypto.randomBytes(16);
const hash = crypto.scryptSync(password, salt, 64);
console.log(`scrypt$${salt.toString('hex')}$${hash.toString('hex')}`);
