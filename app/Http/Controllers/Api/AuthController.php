<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function register(Request $request){
        try{
            $validated = $request->validate([
                'name' => 'required|string|max:255',
                'email'=> 'required|email|unique:users,email',
                'password'=>'required|string|min:6',
                'phone'=>'nullable|string|max:20',
            ]);    
        } catch (ValidationException $e){
            return response()->json([
                'message'=>'Failed to register user',
                'errors'=>$e->errors()
            ], 422);
        }

        $validated['password']=Hash::make($validated['password']);
        $validated['remember_token']=Str::random(10);

        $user = User::create($validated);

        return response()->json([
            'message' => 'User created successfully',
            'user'=> [
                'id' => $user->id,
                'name'=> $user->name,
                'email'=> $user->email,
                'phone'=>$user->phone,

            ]
        ], 201);

    }

    public function login(Request $request){
        try{
            $credentials = $request->validate([
                'email'=>'required|email',
                'password'=>'required|string'
            ]);
        } catch (ValidationException $e){
            return response()->json([
                'message'=>'Failed to login',
                'errors'=>$e->errors()
            ], 422);
        }

        $user = User::where('email', $credentials['email'])->first();

        if(!$user || !Hash::check($credentials['password'], $user->password)){
            return response()->json([
                'message'=>'The provided credentials are incorrect.'
            ], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message'=>'Login successful',
            'access_token'=>$token,
            'token_type'=>'Bearer'
        ], 200);
    }

    public function logout(Request $request){
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message'=>'Logged out successfully'
        ], 200);
    }
}
