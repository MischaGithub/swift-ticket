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
