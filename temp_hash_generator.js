const bcrypt = require('bcrypt');

const newPassword = 'admin'; // <-- Change this to your desired password
const saltRounds = 10;

bcrypt.hash(newPassword, saltRounds, (err, hash) => {
  if (err) {
    console.error('Error generating hash:', err);
    return;
  }
  console.log('New Password Hash:');
  console.log(hash);
  // This is the hash you'll copy
  process.exit();
});