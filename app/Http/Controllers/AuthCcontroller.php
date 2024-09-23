<?php

namespace App\Http\Controllers;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AuthCcontroller extends Controller
{
    public function login(Request $request)
    {

        // Validate
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:5'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $dataValidated = auth()->attempt($validator->validated());

        if (!$dataValidated) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        // Tạo Access Token
        $accessTokenPayload = [
            'sub' => auth()->user(),
            'iat' => time(),
            'exp' => time() + 300, // Tồn tại trong 5 phút
        ];

        $accessToken = $this->createJwtToken($accessTokenPayload);

        // Tạo Refresh Token
        $refreshTokenPayload = [
            'sub' => auth()->user(),
            'iat' => time(),
            'exp' => time() + 3600, // Tồn tại trong 1h
        ];

        $refreshToken = $this->createJwtToken($refreshTokenPayload);


        return $this->respondWithToken($accessToken, $refreshToken);
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password)]
        ));

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }

    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    public function refresh(Request $request)
    {
        $refreshToken = $request->rerefreshToken;


        try {
            $payload = $this->decodeJwtToken($refreshToken);
            if (time() >= $refreshToken->exp) {
                return response()->json(
                    ['message' => 'Không bỏ refresh token'],
                    400
                );
            }
        } catch (\Throwable $th) {
            //throw $th;
        }
        if (!$refreshToken) {
            return response()->json(
                ['message' => 'Không bỏ refresh token'],
                400
            );
        }
    }

    public function userProfile(Request $request)
    {
        $token = $request->bearerToken();

        $payloadData = $this->decodeJwtToken($token);

        return response()->json($payloadData);
    }

    protected function respondWithToken($accessToken, $refreshToken)
    {
        $payloadData = $this->decodeJwtToken($accessToken);
        $expired = Carbon::createFromTimestamp($payloadData->exp);
        $expiredTime = $expired->format('Y-m-d H:i:s');

        return response()->json([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => $expiredTime,
            'user' => auth()->user(),
        ]);
    }

    protected function createJwtToken($data)
    {
        // Tạo Header và mã hóa
        $header = json_encode([
            'typ' => 'JWT',
            'alg' => 'HS256',
        ]);
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));

        // Tạo Payload và mã hóa
        $payload = json_encode($data);
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

        // Tạo Signature và mã hóa
        $singnature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, 'abc123!@#', true);
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($singnature));

        $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

        return $jwt;
    }

    protected function decodeJwtToken($token)
    {

        // Tách thành phần
        $tokenParts = explode('.', $token);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signatureProvided = $tokenParts[2];

        // Kiểm trả signature
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        // hash_hmac là sử dụng để tạo chữ ký HMAC
        // HMAC kết hợp một hàm băm (như SHA-256) với một khóa bí mật để đảm bảo tính toàn vẹn và tính xác thực của dữ liệu.
        $signature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, 'abc123!@#', true);
        $baser64UrlSignature =  str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        if ($signatureProvided !== $baser64UrlSignature) {
            throw new \Exception('Invalid token signature');
        }
        return json_decode($payload);
    }

    public function changePassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'old_password' => 'required|string|min:6',
            'new_password' => 'required|string|confirmed|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors()->toJson(), 400);
        }
        $userId = auth()->user()->id;

        $user = User::where('id', $userId)->update(
            ['password' => bcrypt($request->new_password)]
        );

        return response()->json([
            'message' => 'User successfully changed password',
            'user' => $user,
        ], 201);
    }
}
