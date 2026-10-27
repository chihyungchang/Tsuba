const { execFile } = require('child_process');
function activate() { execFile('git', ['status'], () => {}); }
module.exports = { activate };
