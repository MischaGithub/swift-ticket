"use server";

import { prisma } from "@/db/prisma";
import bcrypt from "bcryptjs";
import { logEvent } from "@/utils/sentry";
import { signAuthToken, setAuthCookie, removeAuthCookie } from "@/lib/auth";
import { log } from "console";

type ResponseResult = {
  success: boolean;
  message: string;
};

export async function registerUser(
  prevState: ResponseResult,
  formData: FormData
): Promise<ResponseResult> {
  try {
    const name = formData.get("name") as string;
    const email = formData.get("email") as string;
    const password = formData.get("password") as string;

    if (!name || !email || !password) {
      logEvent("Validation error", "auth", { name, email }, "warning");
      return {
        success: false,
        message: "All fields are required",
      };
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      logEvent(
        `Registration failed: User already exists - ${email}`,
        "auth",
        { email },
        "warning"
      );

      return {
        success: false,
        message: "user already exists",
      };
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    // Sign and set auth token
    const token = await signAuthToken({ userId: user.id });
    await setAuthCookie(token);

    logEvent(
      `User registered successfully: ${email}`,
      "auth",
      { userId: user.id, email },
      "info"
    );

    return {
      success: true,
      message: "User registered successfully",
    };
  } catch (error) {
    logEvent(
      "Unexpceted error during registration",
      "auth",
      {},
      "error",
      error
    );

    return {
      success: false,
      message: "Something went wrong, please try again",
    };
  }
}

export async function logoutUser(): Promise<{
  success: boolean;
  message: string;
}> {
  try {
    await removeAuthCookie();

    logEvent("User logged out successfully", "auth", {}, "info");

    return {
      success: true,
      message: "User logged out successfully",
    };
  } catch (error) {
    logEvent("Unexpected error during logout", "auth", {}, "error", error);

    return {
      success: false,
      message: "Logout failed, please try again",
    };
  }
}

// Log user in
export async function loginUser(
  prevState: ResponseResult,
  formData: FormData
): Promise<ResponseResult> {
  try {
    const email = formData.get("email") as string;
    const password = formData.get("password") as string;

    // Validate user
    // Check if email and password are provided
    if (!email || !password) {
      logEvent(
        "Validation error: Missing login fields",
        "auth",
        { email },
        "warning"
      );
      return {
        success: false,
        message: "Email and password are required",
      };
    }

    // Check if the user exists in the database
    const user = await prisma.user.findUnique({
      where: { email },
    });

    // If user is not found or password is not set, return an error
    // This is to prevent leaking information about whether the email exists
    if (!user || !user.password) {
      logEvent(
        `Login failed: User not found - ${email}`,
        "auth",
        { email },
        "warning"
      );
      return {
        success: false,
        message: "Invalid email or password",
      };
    }

    // Compare the provided password with the hashed password in the database
    // This is a secure way to check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);

    // If the password is invalid, return an error
    if (!isPasswordValid) {
      logEvent("Login failed: Invalid password", "auth", { email }, "warning");
      return {
        success: false,
        message: "Invalid email or password",
      };
    }

    // If the password is valid, sign a new auth token
    // and set it in the cookie
    // This token will be used to authenticate the user in future requests
    const token = await signAuthToken({ userId: user.id });
    await setAuthCookie(token);

    return { success: true, message: "Login successful" };
  } catch (error) {
    // Log the error and return a generic message
    logEvent("Unexpected error during login", "auth", {}, "error", error);
    return {
      success: false,
      message: "Error during login, please try again",
    };
  }
}
