package me.weishu.kernelsu.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import me.weishu.kernelsu.ui.screen.securityaudit.AuditHistory
import me.weishu.kernelsu.ui.screen.securityaudit.SecurityAuditUiState
import me.weishu.kernelsu.ui.screen.securityaudit.isHighRisk
import me.weishu.kernelsu.ui.screen.securityaudit.parseAuditHistories
import me.weishu.kernelsu.ui.screen.securityaudit.parseStaleAuditModuleIds
import me.weishu.kernelsu.ui.util.getModuleAuditHistories
import me.weishu.kernelsu.ui.util.getStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.pruneStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.rescanInstalledModules as runInstalledModuleRescan

class SecurityAuditViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(SecurityAuditUiState())
    val uiState: StateFlow<SecurityAuditUiState> = _uiState.asStateFlow()
    private var refreshJob: Job? = null

    fun refresh() {
        refreshJob?.cancel()
        refreshJob = viewModelScope.launch(Dispatchers.IO) {
            _uiState.update { state ->
                state.copy(
                    isLoading = state.histories.isEmpty(),
                    isRefreshing = state.histories.isNotEmpty(),
                    isRescanning = state.isRescanning,
                    errorMessage = null,
                )
            }
            runCatching {
                val histories = parseAuditHistories(getModuleAuditHistories())
                    .sortedWith(
                        compareByDescending<AuditHistory> { it.isHighRisk() }
                            .thenByDescending { history ->
                                history.events.maxOfOrNull { it.timestampUnixSeconds } ?: 0L
                            }
                    )
                histories to parseStaleAuditModuleIds(getStaleModuleAuditHistories())
            }.onSuccess { (histories, staleModuleIds) ->
                _uiState.value = SecurityAuditUiState(
                    isLoading = false,
                    isRescanning = _uiState.value.isRescanning,
                    isPruning = _uiState.value.isPruning,
                    histories = histories,
                    staleModuleIds = staleModuleIds,
                )
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        isRefreshing = false,
                        errorMessage = error.message ?: error::class.java.simpleName,
                    )
                }
            }
        }
    }

    fun rescanInstalledModules() {
        if (_uiState.value.isRescanning || _uiState.value.isPruning) return
        viewModelScope.launch(Dispatchers.IO) {
            _uiState.update { it.copy(isRescanning = true, errorMessage = null) }
            runCatching {
                runInstalledModuleRescan()
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(errorMessage = error.message ?: error::class.java.simpleName)
                }
            }
            _uiState.update { it.copy(isRescanning = false) }
            refresh()
        }
    }

    fun pruneStaleAuditHistories() {
        if (
            _uiState.value.isPruning ||
            _uiState.value.isRescanning ||
            _uiState.value.staleModuleIds.isEmpty()
        ) return
        viewModelScope.launch(Dispatchers.IO) {
            _uiState.update { it.copy(isPruning = true, errorMessage = null) }
            val result = runCatching {
                pruneStaleModuleAuditHistories()
            }
            result.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(
                        isPruning = false,
                        errorMessage = error.message ?: error::class.java.simpleName,
                    )
                }
            }
            if (result.isSuccess) {
                _uiState.update { it.copy(isPruning = false) }
                refresh()
            }
        }
    }
}
