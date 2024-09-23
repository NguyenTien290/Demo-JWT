<?php

use App\Http\Controllers\AuthCcontroller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::group(['prefix' => 'auth'], function ($router) {
    Route::post('/login', [AuthCcontroller::class, 'login']);
    Route::post('/register', [AuthCcontroller::class, 'register']);
    Route::group(['middleware' => ['jwt']], function () {
        Route::get('/user-profile', [AuthCcontroller::class, 'userProfile']);
        Route::post('/logout', [AuthCcontroller::class, 'logout']);
        Route::post('/refresh', [AuthCcontroller::class, 'refresh']);
        Route::post('/change-pass', [AuthCcontroller::class, 'changePassWord']);
    });
});
