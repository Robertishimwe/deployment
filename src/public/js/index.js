const loginForm = document.getElementById('loginForm');
const spinner = document.getElementById('spinner');
spinner.style.display = 'none';

const login = () => {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const userData = {
        email,
        password,
    };
    const fetchData = {
        method: 'POST',
        body: JSON.stringify(userData),
        headers: new Headers({
            'Content-Type': 'application/json; charset=UTF-8',
        }),
    };

    fetch('https://barefoot.onrender.com/api/auth/login', fetchData)
        .then((response) => response.json())
        .then((data) => {
            console.log(data);

            sessionStorage.setItem('accessToken', JSON.stringify(data.token));
            if (data.message === 'User login successful :)') {
                setTimeout(() => {
                    window.location = './username.html';
                }, 3000);
            } else {
                alert('invalid credential,Try again'); // eslint-disable-line no-alert
            }
        });
    console.log('request sent');
};

loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    spinner.style.display = 'block';
    spinner.innerHTML = `
  <img src="https://raw.githubusercontent.com/Steve-Ndicunguye/ATLP-Portfolio/master/images/Spinner.gif" alt="loading..." width="40px" height="40px">`;
    login();
});