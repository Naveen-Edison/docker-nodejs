const fs = require('fs');


// Reads the email template html files from templates folder.

var readHTMLFile = function(path, callback) {
  fs.readFile(path, { encoding: 'utf-8' }, function(err, html) {
    if (err) {
      throw err;
    } else {
      callback(null, html);
    }
  });
};

module.exports = readHTMLFile;
