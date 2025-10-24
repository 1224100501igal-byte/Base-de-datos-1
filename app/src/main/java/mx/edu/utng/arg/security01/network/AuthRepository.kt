package mx.edu.utng.arg.security01.network

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mx.edu.utng.arg.security01.models.LoginRequest
import mx.edu.utng.arg.security01.models.User
import mx.edu.utng.arg.security01.security.SecureStorage

class AuthRepository(context: Context) {

    private val secureStorage = SecureStorage(context)
    // Comentamos la API real temporalmente
    // private val apiService = RetrofitClient.apiService

    companion object {
        private const val TAG = "AuthRepository"
        private const val USE_MOCK_API = true // ⚠️ CAMBIAR A FALSE EN PRODUCCIÓN
    }

    suspend fun login(email: String, password: String): Result<User> {
        return withContext(Dispatchers.IO) {
            try {
                if (email.isBlank() || password.isBlank()) {
                    return@withContext Result.failure(
                        Exception("El email y la contraseña son obligatorios")
                    )
                }

                if (!android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
                    return@withContext Result.failure(
                        Exception("El formato del email no es válido")
                    )
                }

                Log.d(TAG, "Intentando login para usuario: $email")

                val loginRequest = LoginRequest(email, password)

                // ⚠️ USAR MOCK PARA PRUEBAS
                val response = if (USE_MOCK_API) {
                    MockApiService.login(loginRequest)
                } else {
                    RetrofitClient.apiService.login(loginRequest)
                }

                if (response.isSuccessful) {
                    val loginResponse = response.body()

                    if (loginResponse?.success == true && loginResponse.user != null) {
                        val user = loginResponse.user
                        secureStorage.saveUserSession(user)

                        Log.d(TAG, "Login exitoso para: $email")
                        Result.success(user)
                    } else {
                        Log.w(TAG, "Login fallido: ${loginResponse?.message}")
                        Result.failure(
                            Exception(loginResponse?.message ?: "Error en el login")
                        )
                    }
                } else {
                    val errorMessage = when (response.code()) {
                        401 -> "Credenciales incorrectas"
                        404 -> "Servicio no disponible"
                        500 -> "Error en el servidor"
                        else -> "Error de conexión: ${response.code()}"
                    }
                    Log.e(TAG, "Error HTTP: ${response.code()}")
                    Result.failure(Exception(errorMessage))
                }

            } catch (e: Exception) {
                Log.e(TAG, "Excepción en login", e)
                Result.failure(
                    Exception("Error de conexión: ${e.localizedMessage}")
                )
            }
        }
    }
    // Resto de funciones igual...
    // validateToken, logout, etc. también deben usar USE_MOCK_API
}
