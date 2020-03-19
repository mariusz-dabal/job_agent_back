<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

// register/login
$router->post('/register', 'AuthController@register');
$router->post('/login', 'AuthController@login');
$router->post('/logout', [
    'middleware' => 'auth',
    'uses' => 'AuthController@logout']);

$router->get('/', function () use ($router) {
    return $router->app->version();
});

$router->get('users', 'UserController@index');
