const express = require('express');
const request = require('request');
const app = express();

app.get('/external', (req, res) => {
    const url = 'https://yandex.ru/maps'; // URL внешней страницы
    request(url, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            res.send(body);
        } else {
            res.status(500).send('Ошибка при получении содержимого');
        }
    });
});

app.listen(3000, () => {
    console.log('Сервер запущен на порту 3000');
});
