const crypto = require('crypto');

global.crypto = {
  getRandomValues: (arr) => {
    return crypto.randomBytes(arr.length);
  },
};
