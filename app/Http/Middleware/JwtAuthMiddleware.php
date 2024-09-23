<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class JwtAuthMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next)
    {

        $token = $request->bearerToken();

        try {
            // Giải mã token,
            $payload = $this->decodeJwtToken($token);

            if(time() >= $payload->exp){
                return response()->json(['message' => 'Token has expired'], 401);
            }
        } catch (\Exception $e) {
            return response()->json(['message' => 'Invalid token', 'error' => $e->getMessage()], 401);
        }

        return $next($request);
    }

    protected function decodeJwtToken($token){
        
        // Tách thành phần
        $tokenParts = explode('.', $token);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signatureProvided = $tokenParts[2];

        // Kiểm trả signature
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        
        $signature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, 'abc123!@#', true);
        $baser64UrlSignature =  str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        if($signatureProvided !== $baser64UrlSignature){
            throw new \Exception('Invalid token signature');
        }
        return json_decode($payload) ;
    }
}
