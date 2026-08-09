const API_KEY = "sk-1234567890abcdef";
const dbUrl = "postgresql://postgres:mypassword123@localhost:5432/mydb";
const jwtSecret = "supersecretjwtkey123";

function queryUser(id) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
}

function renderContent(html) {
  document.getElementById('content').innerHTML = html;
}

app.use(cors({ origin: '*' }));

function processInput(input) {
  eval(input);
}
