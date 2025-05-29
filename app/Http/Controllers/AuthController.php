<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(RegisterRequest $request){
        try {
            $validated = $request->validated();

            $user = User::create([
                'name' => $validated['name'],
                'email' => $validated['email'],
                'password' => Hash::make($validated['password'])
            ]);

            $token = $user->createToken('auth_token')->plainTextToken;
            $expirationTime = 60 * 24 * 30;

            $user->tokens()->orderBy('created_at', 'desc')->first()->update([
                'expires_at' => now()->addMinutes($expirationTime)
            ]);

            return response()->json([
                'success' => true,
                'message' => 'User registered successfully',
                'token' => $token,
                'user' => $user->fresh(),
            ])->cookie('token', $token, $expirationTime);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Registration failed',
                'errors' => ['general' => ['Unable to create account. Please try again.']]
            ], 500);
        }
    }

    public function login(LoginRequest $request) {
        $credentials = $request->validated();
        $user = User::where('email', $credentials['email'])->first();

        if (!$user || !Hash::check($credentials['password'], $user->password)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid credentials',
                'errors' => ['credentials' => ['Email or password is incorrect']]
            ], 401);
        }

        try {
            $token = $user->createToken('auth_token')->plainTextToken;
            $expirationTime = 60 * 24 * 30;

            $user->tokens()->orderBy('created_at', 'desc')->first()->update([
                'expires_at' => now()->addMinutes($expirationTime)
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Login successful',
                'token' => $token,
                'user' => $user->fresh(),
            ])->cookie('token', $token, $expirationTime);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Login failed',
                'errors' => ['general' => ['Unable to complete login. Please try again.']]
            ], 500);
        }
    }

    public function logout(Request $request){
        $user = $request->user();

        if (!$user) {
            return response()->json([
                "error" => "User not found!"
            ], 404);
        }

        // delete the teken
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logged out successfully'
        ]);
    }

    public function me(Request $request)
    {
        try {
            $user = $request->user();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not authenticated'
                ], 401);
            }

            return response()->json([
                'success' => true,
                'user' => $user
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to get user data'
            ], 500);
        }
    }
}
