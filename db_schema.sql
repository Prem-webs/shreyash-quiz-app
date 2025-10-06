const bcrypt = require('bcrypt');
const password = 'admin'; // <--- CHOOSE YOUR NEW PASSWORD HERE

bcrypt.hash(password, 10, (err, hash) => {
    if (err) throw err;
    console.log("--- COPY THIS HASH ---");
    console.log(hash);
    console.log("----------------------");
    process.exit();
});