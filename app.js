require('dotenv').config();
require('./config/connection');

const app = require('./routes/route');
const port = process.env.PORT || 3000;



app.listen(port, () => {
  console.log('App listening on port 3000!');
});
