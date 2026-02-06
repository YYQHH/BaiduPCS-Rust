// 转存 API 处理器

use crate::server::AppState;
use crate::transfer::{TransferStatus, TransferTask};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

/// API 响应结构
#[derive(Debug, Serialize)]
pub struct TransferApiResponse<T> {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> TransferApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "success".to_string(),
            data: Some(data),
        }
    }

    pub fn error(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }
}

/// 业务响应码
pub mod error_codes {
    /// 需要提取码
    pub const NEED_PASSWORD: i32 = 1001;
    /// 提取码错误
    pub const INVALID_PASSWORD: i32 = 1002;
    /// 分享已失效
    pub const SHARE_EXPIRED: i32 = 1003;
    /// 分享不存在
    pub const SHARE_NOT_FOUND: i32 = 1004;
    /// 转存管理器未初始化
    pub const MANAGER_NOT_READY: i32 = 1005;
    /// 任务不存在
    pub const TASK_NOT_FOUND: i32 = 1006;
    /// 网盘空间不足
    pub const INSUFFICIENT_SPACE: i32 = 1007;
    /// 转存失败
    pub const TRANSFER_FAILED: i32 = 1008;
    /// 下载失败
    pub const DOWNLOAD_FAILED: i32 = 1009;
}

// ============================================
// 请求/响应结构
// ============================================

/// 创建转存任务请求
#[derive(Debug, Deserialize)]
pub struct CreateTransferRequest {
    /// 分享链接
    pub share_url: String,
    /// 提取码（可选）
    pub password: Option<String>,
    /// 网盘保存路径（分享直下模式下可省略，后端自动生成临时目录）
    #[serde(default)]
    pub save_path: String,
    /// 网盘保存目录 fs_id
    #[serde(default)]
    pub save_fs_id: u64,
    /// 是否自动下载（不传使用全局配置）
    pub auto_download: Option<bool>,
    /// 本地下载路径（auto_download=true 时可选）
    pub local_download_path: Option<String>,
    /// 是否为分享直下任务
    /// 分享直下任务会自动创建临时目录，下载完成后自动清理
    #[serde(default)]
    pub is_share_direct_download: bool,
}

/// 创建转存任务响应
#[derive(Debug, Serialize)]
pub struct CreateTransferResponse {
    /// 任务 ID（创建成功时返回）
    pub task_id: Option<String>,
    /// 任务状态
    pub status: Option<TransferStatus>,
    /// 是否需要提取码
    pub need_password: bool,
}

/// 转存任务列表查询参数
#[derive(Debug, Deserialize, Default)]
pub struct TransferListQuery {
    /// 过滤：是否为分享直下任务（可选）
    pub is_share_direct_download: Option<bool>,
}

/// 转存任务列表响应
#[derive(Debug, Serialize)]
pub struct TransferListResponse {
    pub tasks: Vec<TransferTask>,
    pub total: usize,
}

// ============================================
// API 处理器
// ============================================

/// POST /api/v1/transfers
/// 创建转存任务
pub async fn create_transfer(
    State(app_state): State<AppState>,
    Json(req): Json<CreateTransferRequest>,
) -> Json<TransferApiResponse<CreateTransferResponse>> {
    // 获取转存管理器
    let transfer_manager = {
        let guard = app_state.transfer_manager.read().await;
        match guard.clone() {
            Some(tm) => tm,
            None => {
                error!("转存管理器未初始化");
                return Json(TransferApiResponse::error(
                    error_codes::MANAGER_NOT_READY,
                    "转存管理器未初始化，请先登录",
                ));
            }
        }
    };

    // 创建转存请求
    let create_request = crate::transfer::manager::CreateTransferRequest {
        share_url: req.share_url,
        password: req.password,
        save_path: req.save_path,
        save_fs_id: req.save_fs_id,
        auto_download: req.auto_download,
        local_download_path: req.local_download_path,
        is_share_direct_download: req.is_share_direct_download,
    };

    // 创建任务
    match transfer_manager.create_task(create_request).await {
        Ok(response) => {
            if response.need_password {
                return Json(TransferApiResponse::error(
                    error_codes::NEED_PASSWORD,
                    response.error.unwrap_or_else(|| "需要提取码".to_string()),
                ));
            }

            if let Some(ref err) = response.error {
                // 根据错误内容返回不同的错误码
                let code = if err.contains("需要密码") || err.contains("需要提取码") {
                    error_codes::NEED_PASSWORD
                } else if err.contains("提取码错误") {
                    error_codes::INVALID_PASSWORD
                } else if err.contains("已失效") {
                    error_codes::SHARE_EXPIRED
                } else if err.contains("不存在") {
                    error_codes::SHARE_NOT_FOUND
                } else if err.contains("空间不足") {
                    error_codes::INSUFFICIENT_SPACE
                } else {
                    -1
                };

                return Json(TransferApiResponse::error(code, err.clone()));
            }

            info!("转存任务创建成功: task_id={:?}", response.task_id);
            Json(TransferApiResponse::success(CreateTransferResponse {
                task_id: response.task_id,
                status: response.status,
                need_password: false,
            }))
        }
        Err(e) => {
            let err_msg = e.to_string();

            error!("创建转存任务失败: {:?}", err_msg);

            // 根据错误内容返回不同的错误码
            let code = if err_msg.contains("提取码错误") {
                error_codes::INVALID_PASSWORD
            } else if err_msg.contains("已失效") {
                error_codes::SHARE_EXPIRED
            } else if err_msg.contains("不存在") {
                error_codes::SHARE_NOT_FOUND
            } else if err_msg.contains("空间不足") {
                error_codes::INSUFFICIENT_SPACE
            } else {
                -1
            };

            Json(TransferApiResponse::error(code, err_msg))
        }
    }
}

/// GET /api/v1/transfers
/// 获取所有转存任务
/// 支持查询参数：is_share_direct_download (可选，过滤分享直下任务)
pub async fn get_all_transfers(
    State(app_state): State<AppState>,
    Query(query): Query<TransferListQuery>,
) -> Result<Json<TransferApiResponse<TransferListResponse>>, StatusCode> {
    let transfer_manager = {
        let guard = app_state.transfer_manager.read().await;
        guard.clone().ok_or(StatusCode::SERVICE_UNAVAILABLE)?
    };

    let mut tasks = transfer_manager.get_all_tasks().await;

    // 按 is_share_direct_download 过滤（如果指定）
    if let Some(is_share_direct) = query.is_share_direct_download {
        tasks.retain(|task| task.is_share_direct_download == is_share_direct);
    }

    // 按创建时间降序排序（最新的在前）
    tasks.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let total = tasks.len();

    Ok(Json(TransferApiResponse::success(TransferListResponse {
        tasks,
        total,
    })))
}

/// GET /api/v1/transfers/:id
/// 获取单个转存任务
pub async fn get_transfer(
    State(app_state): State<AppState>,
    Path(task_id): Path<String>,
) -> Json<TransferApiResponse<TransferTask>> {
    let transfer_manager = {
        let guard = app_state.transfer_manager.read().await;
        match guard.clone() {
            Some(tm) => tm,
            None => {
                return Json(TransferApiResponse::error(
                    error_codes::MANAGER_NOT_READY,
                    "转存管理器未初始化",
                ));
            }
        }
    };

    match transfer_manager.get_task(&task_id).await {
        Some(task) => Json(TransferApiResponse::success(task)),
        None => Json(TransferApiResponse::error(
            error_codes::TASK_NOT_FOUND,
            "任务不存在",
        )),
    }
}

/// DELETE /api/v1/transfers/:id
/// 删除转存任务
pub async fn delete_transfer(
    State(app_state): State<AppState>,
    Path(task_id): Path<String>,
) -> Json<TransferApiResponse<String>> {
    info!("删除转存任务: {}", task_id);

    let transfer_manager = {
        let guard = app_state.transfer_manager.read().await;
        match guard.clone() {
            Some(tm) => tm,
            None => {
                return Json(TransferApiResponse::error(
                    error_codes::MANAGER_NOT_READY,
                    "转存管理器未初始化",
                ));
            }
        }
    };

    match transfer_manager.remove_task(&task_id).await {
        Ok(()) => {
            info!("转存任务删除成功: {}", task_id);
            Json(TransferApiResponse::success("ok".to_string()))
        }
        Err(e) => {
            error!("删除转存任务失败: {:?}", e.to_string());
            Json(TransferApiResponse::error(-1, e.to_string()))
        }
    }
}

/// POST /api/v1/transfers/:id/cancel
/// 取消转存任务
pub async fn cancel_transfer(
    State(app_state): State<AppState>,
    Path(task_id): Path<String>,
) -> Json<TransferApiResponse<String>> {
    info!("取消转存任务: {}", task_id);

    let transfer_manager = {
        let guard = app_state.transfer_manager.read().await;
        match guard.clone() {
            Some(tm) => tm,
            None => {
                return Json(TransferApiResponse::error(
                    error_codes::MANAGER_NOT_READY,
                    "转存管理器未初始化",
                ));
            }
        }
    };

    match transfer_manager.cancel_task(&task_id).await {
        Ok(()) => {
            info!("转存任务取消成功: {}", task_id);
            Json(TransferApiResponse::success("ok".to_string()))
        }
        Err(e) => {
            error!("取消转存任务失败: {:?}", e);
            Json(TransferApiResponse::error(-1, e.to_string()))
        }
    }
}

/// 清理孤立目录响应
#[derive(Debug, Serialize)]
pub struct CleanupOrphanedResponse {
    /// 成功删除的目录数
    pub deleted_count: usize,
    /// 删除失败的目录路径列表
    pub failed_paths: Vec<String>,
}

/// POST /api/v1/transfers/cleanup
/// 手动清理孤立的临时目录
///
/// 扫描临时目录下的所有子目录，找出不属于任何活跃任务的目录（孤立目录），
/// 然后删除这些孤立目录。
pub async fn cleanup_orphaned_temp_dirs(
    State(app_state): State<AppState>,
) -> Json<TransferApiResponse<CleanupOrphanedResponse>> {
    info!("手动清理孤立临时目录");

    let transfer_manager = {
        let guard = app_state.transfer_manager.read().await;
        match guard.clone() {
            Some(tm) => tm,
            None => {
                return Json(TransferApiResponse::error(
                    error_codes::MANAGER_NOT_READY,
                    "转存管理器未初始化，请先登录",
                ));
            }
        }
    };

    let result = transfer_manager.cleanup_orphaned_temp_dirs().await;

    if let Some(ref err) = result.error {
        if result.deleted_count == 0 {
            // 完全失败
            return Json(TransferApiResponse::error(-1, err.clone()));
        }
        // 部分成功，仍返回成功但包含失败信息
        info!(
            "孤立目录清理部分成功: 删除={}, 失败={}",
            result.deleted_count,
            result.failed_paths.len()
        );
    } else {
        info!("孤立目录清理成功: 删除={}", result.deleted_count);
    }

    Json(TransferApiResponse::success(CleanupOrphanedResponse {
        deleted_count: result.deleted_count,
        failed_paths: result.failed_paths,
    }))
}
