// This is a test file with real vulnerabilities
const apiKey = "sk-test-1234567890abcdef";
const dbConn = "postgresql://admin:secretpass@db.host.com:5432/prod";
const jwtSecret = "my-super-secret-jwt-key-2024";

function searchUsers(query) {
  return db.query(`SELECT * FROM users WHERE name = ${query}`);
}

function renderPage(userInput) {
  document.body.innerHTML = userInput;
}

app.use(cors({ origin: '*' }));

function runCode(code) {
  return eval(code);
}
