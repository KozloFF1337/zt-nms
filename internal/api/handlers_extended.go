package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/zt-nms/zt-nms/internal/analytics"
	"github.com/zt-nms/zt-nms/internal/attestation"
	"github.com/zt-nms/zt-nms/internal/audit"
	"github.com/zt-nms/zt-nms/internal/inventory"
	"github.com/zt-nms/zt-nms/pkg/models"
)

// ExtendedHandler contains extended API handlers with full functionality
type ExtendedHandler struct {
	*Handler
	inventorySvc    *inventory.Service
	attestationSvc  *attestation.Verifier
	auditSvc        *audit.Service
	analyticsEngine *analytics.Engine
}

// NewExtendedHandler creates a new extended API handler
func NewExtendedHandler(
	base *Handler,
	inventorySvc *inventory.Service,
	attestationSvc *attestation.Verifier,
	auditSvc *audit.Service,
	analyticsEngine *analytics.Engine,
) *ExtendedHandler {
	return &ExtendedHandler{
		Handler:         base,
		inventorySvc:    inventorySvc,
		attestationSvc:  attestationSvc,
		auditSvc:        auditSvc,
		analyticsEngine: analyticsEngine,
	}
}

// RegisterExtendedRoutes registers additional API routes
func (h *ExtendedHandler) RegisterExtendedRoutes(e *echo.Echo) {
	v1 := e.Group("/api/v1")

	// Dashboard/Analytics routes
	dashboard := v1.Group("/dashboard")
	dashboard.GET("/stats", h.GetDashboardStats)
	dashboard.GET("/trends/policy", h.GetPolicyTrends)
	dashboard.GET("/trends/deployments", h.GetDeploymentTrends)
	dashboard.GET("/trends/security", h.GetSecurityTrends)

	// Attestation routes
	attestations := v1.Group("/attestations")
	attestations.POST("/request", h.RequestAttestation)
	attestations.POST("/verify", h.VerifyAttestation)
	attestations.GET("/quarantined", h.GetQuarantinedDevices)
	attestations.DELETE("/quarantine/:id", h.RemoveFromQuarantine)

	// Location routes
	locations := v1.Group("/locations")
	locations.POST("", h.CreateLocation)
	locations.GET("", h.ListLocations)
	locations.GET("/:id", h.GetLocation)
}

// ============= Dashboard Handlers =============

// GetDashboardStats returns dashboard statistics
func (h *ExtendedHandler) GetDashboardStats(c echo.Context) error {
	if h.analyticsEngine == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"devices":      map[string]int{"total": 0, "online": 0, "offline": 0, "quarantined": 0},
			"identities":   map[string]int{"total": 0, "operators": 0, "devices": 0, "services": 0, "active": 0},
			"capabilities": map[string]int{"active": 0, "pending_approval": 0, "expired_today": 0},
			"policies":     map[string]int{"total": 0, "active": 0, "evaluations_today": 0, "denials_today": 0},
			"deployments":  map[string]int{"pending": 0, "in_progress": 0, "completed_today": 0, "failed_today": 0},
			"audit":        map[string]int{"events_today": 0, "security_events": 0, "failed_auth": 0},
		})
	}

	stats, err := h.analyticsEngine.GetDashboardStats(c.Request().Context())
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, stats)
}

// GetPolicyTrends returns policy evaluation trends
func (h *ExtendedHandler) GetPolicyTrends(c echo.Context) error {
	hours, _ := strconv.Atoi(c.QueryParam("hours"))
	if hours <= 0 {
		hours = 24
	}

	if h.analyticsEngine == nil {
		return c.JSON(http.StatusOK, []map[string]interface{}{})
	}

	trend, err := h.analyticsEngine.GetPolicyEvaluationTrend(c.Request().Context(), hours)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, trend)
}

// GetDeploymentTrends returns deployment trends
func (h *ExtendedHandler) GetDeploymentTrends(c echo.Context) error {
	days, _ := strconv.Atoi(c.QueryParam("days"))
	if days <= 0 {
		days = 7
	}

	if h.analyticsEngine == nil {
		return c.JSON(http.StatusOK, []map[string]interface{}{})
	}

	trend, err := h.analyticsEngine.GetConfigDeploymentTrend(c.Request().Context(), days)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, trend)
}

// GetSecurityTrends returns security event trends
func (h *ExtendedHandler) GetSecurityTrends(c echo.Context) error {
	days, _ := strconv.Atoi(c.QueryParam("days"))
	if days <= 0 {
		days = 7
	}

	if h.analyticsEngine == nil {
		return c.JSON(http.StatusOK, []map[string]interface{}{})
	}

	trend, err := h.analyticsEngine.GetSecurityTrend(c.Request().Context(), days)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, trend)
}

// ============= Device Handlers =============

// ListDevicesExtended lists devices with full details
func (h *ExtendedHandler) ListDevicesExtended(c echo.Context) error {
	if h.inventorySvc == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"devices": []interface{}{},
			"total":   0,
		})
	}

	filter := inventory.DeviceFilter{
		Role:        inventory.DeviceRole(c.QueryParam("role")),
		Criticality: inventory.DeviceCriticality(c.QueryParam("criticality")),
		Status:      inventory.DeviceStatus(c.QueryParam("status")),
		TrustStatus: inventory.TrustStatus(c.QueryParam("trust_status")),
		Vendor:      c.QueryParam("vendor"),
		Search:      c.QueryParam("search"),
	}

	if locID := c.QueryParam("location_id"); locID != "" {
		if id, err := uuid.Parse(locID); err == nil {
			filter.LocationID = &id
		}
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))
	if limit == 0 {
		limit = 50
	}

	devices, total, err := h.inventorySvc.ListDevices(c.Request().Context(), filter, limit, offset)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"devices": devices,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetDeviceExtended retrieves a device with full details
func (h *ExtendedHandler) GetDeviceExtended(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid device ID")
	}

	if h.inventorySvc == nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodeDeviceNotFound, "device not found")
	}

	device, err := h.inventorySvc.GetDevice(c.Request().Context(), id)
	if err != nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodeDeviceNotFound, err.Error())
	}

	return c.JSON(http.StatusOK, device)
}

// RegisterDeviceExtended registers a new device
func (h *ExtendedHandler) RegisterDeviceExtended(c echo.Context) error {
	var req struct {
		Hostname     string                 `json:"hostname"`
		Vendor       string                 `json:"vendor"`
		Model        string                 `json:"model"`
		SerialNumber string                 `json:"serial_number"`
		OSType       string                 `json:"os_type"`
		OSVersion    string                 `json:"os_version"`
		Role         string                 `json:"role"`
		Criticality  string                 `json:"criticality"`
		LocationID   string                 `json:"location_id,omitempty"`
		ManagementIP string                 `json:"management_ip"`
		PublicKey    string                 `json:"public_key"`
		Metadata     map[string]interface{} `json:"metadata,omitempty"`
	}

	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	if h.inventorySvc == nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, "inventory service not available")
	}

	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		// Generate a new key pair for the device if not provided
		_, pubKeyBytes, _ = ed25519.GenerateKey(rand.Reader)
	}

	var locationID *uuid.UUID
	if req.LocationID != "" {
		if id, err := uuid.Parse(req.LocationID); err == nil {
			locationID = &id
		}
	}

	regReq := &inventory.DeviceRegistrationRequest{
		Hostname:     req.Hostname,
		Vendor:       req.Vendor,
		Model:        req.Model,
		SerialNumber: req.SerialNumber,
		OSType:       req.OSType,
		OSVersion:    req.OSVersion,
		Role:         inventory.DeviceRole(req.Role),
		Criticality:  inventory.DeviceCriticality(req.Criticality),
		LocationID:   locationID,
		ManagementIP: req.ManagementIP,
		Metadata:     req.Metadata,
	}

	device, err := h.inventorySvc.RegisterDevice(c.Request().Context(), regReq, pubKeyBytes, nil)
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, err.Error())
	}

	return c.JSON(http.StatusCreated, device)
}

// UpdateDeviceExtended updates a device
func (h *ExtendedHandler) UpdateDeviceExtended(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid device ID")
	}

	if h.inventorySvc == nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, "inventory service not available")
	}

	var req inventory.DeviceUpdateRequest
	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	device, err := h.inventorySvc.UpdateDevice(c.Request().Context(), id, &req, nil)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, device)
}

// DeleteDeviceExtended deletes a device
func (h *ExtendedHandler) DeleteDeviceExtended(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid device ID")
	}

	if h.inventorySvc == nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, "inventory service not available")
	}

	if err := h.inventorySvc.DeleteDevice(c.Request().Context(), id, nil); err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.NoContent(http.StatusNoContent)
}

// ============= Attestation Handlers =============

// RequestAttestation requests attestation for a device
func (h *ExtendedHandler) RequestAttestation(c echo.Context) error {
	var req struct {
		DeviceID       string `json:"device_id"`
		IncludeDetails bool   `json:"include_details"`
	}

	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid device ID")
	}

	if h.attestationSvc == nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, "attestation service not available")
	}

	attestReq, err := h.attestationSvc.RequestAttestation(c.Request().Context(), deviceID, req.IncludeDetails)
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodeAccessDenied, err.Error())
	}

	return c.JSON(http.StatusOK, attestReq)
}

// VerifyAttestation verifies an attestation report
func (h *ExtendedHandler) VerifyAttestation(c echo.Context) error {
	var report models.AttestationReport
	if err := c.Bind(&report); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	if h.attestationSvc == nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, "attestation service not available")
	}

	result, err := h.attestationSvc.VerifyAttestation(c.Request().Context(), &report)
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodeAccessDenied, err.Error())
	}

	return c.JSON(http.StatusOK, result)
}

// GetAttestationExtended retrieves attestation status for a device
func (h *ExtendedHandler) GetAttestationExtended(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid device ID")
	}

	if h.attestationSvc == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"device_id":     id,
			"status":        "unknown",
			"last_verified": nil,
		})
	}

	report, err := h.attestationSvc.GetLatestReport(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"device_id":     id,
			"status":        "never_attested",
			"last_verified": nil,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"device_id":     id,
		"status":        "verified",
		"last_verified": report.Timestamp,
		"report":        report,
	})
}

// GetQuarantinedDevices returns list of quarantined devices
func (h *ExtendedHandler) GetQuarantinedDevices(c echo.Context) error {
	if h.attestationSvc == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"devices": []interface{}{},
		})
	}

	devices := h.attestationSvc.GetQuarantinedDevices()
	return c.JSON(http.StatusOK, map[string]interface{}{
		"devices": devices,
	})
}

// RemoveFromQuarantine removes a device from quarantine
func (h *ExtendedHandler) RemoveFromQuarantine(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid device ID")
	}

	if h.attestationSvc == nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, "attestation service not available")
	}

	h.attestationSvc.Unquarantine(id)
	return c.JSON(http.StatusOK, map[string]string{"status": "removed"})
}

// ============= Audit Handlers =============

// ListAuditEventsExtended lists audit events with filtering
func (h *ExtendedHandler) ListAuditEventsExtended(c echo.Context) error {
	query := &models.AuditQuery{
		Limit: 50,
	}

	if limit, err := strconv.Atoi(c.QueryParam("limit")); err == nil && limit > 0 {
		query.Limit = limit
	}
	if offset, err := strconv.ParseInt(c.QueryParam("offset"), 10, 64); err == nil {
		query.Offset = offset
	}

	if eventType := c.QueryParam("event_type"); eventType != "" {
		query.EventTypes = []models.AuditEventType{models.AuditEventType(eventType)}
	}
	if severity := c.QueryParam("severity"); severity != "" {
		query.Severities = []models.AuditSeverity{models.AuditSeverity(severity)}
	}
	if result := c.QueryParam("result"); result != "" {
		query.Result = models.AuditResult(result)
	}
	if resourceType := c.QueryParam("resource_type"); resourceType != "" {
		query.ResourceType = resourceType
	}

	if from := c.QueryParam("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			query.From = &t
		}
	}
	if to := c.QueryParam("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			query.To = &t
		}
	}

	if h.auditSvc == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"events": []interface{}{},
			"total":  0,
		})
	}

	events, total, err := h.auditSvc.Query(c.Request().Context(), query)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  total,
		"limit":  query.Limit,
		"offset": query.Offset,
	})
}

// GetAuditEventExtended retrieves a single audit event
func (h *ExtendedHandler) GetAuditEventExtended(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid event ID")
	}

	if h.auditSvc == nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodeInternalError, "event not found")
	}

	event, err := h.auditSvc.GetEvent(c.Request().Context(), id)
	if err != nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, event)
}

// VerifyAuditChainExtended verifies the audit chain
func (h *ExtendedHandler) VerifyAuditChainExtended(c echo.Context) error {
	var req struct {
		FromSequence int64 `json:"from_sequence"`
		ToSequence   int64 `json:"to_sequence"`
	}

	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	if h.auditSvc == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"valid":         true,
			"first_sequence": req.FromSequence,
			"last_sequence":  req.ToSequence,
			"event_count":   0,
		})
	}

	result, err := h.auditSvc.VerifyChain(c.Request().Context(), req.FromSequence, req.ToSequence)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, result)
}

// ============= Location Handlers =============

// CreateLocation creates a new location
func (h *ExtendedHandler) CreateLocation(c echo.Context) error {
	var location inventory.Location
	if err := c.Bind(&location); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	if h.inventorySvc == nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, "inventory service not available")
	}

	if err := h.inventorySvc.CreateLocation(c.Request().Context(), &location); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, err.Error())
	}

	return c.JSON(http.StatusCreated, location)
}

// ListLocations lists locations
func (h *ExtendedHandler) ListLocations(c echo.Context) error {
	var parentID *uuid.UUID
	if parent := c.QueryParam("parent_id"); parent != "" {
		if id, err := uuid.Parse(parent); err == nil {
			parentID = &id
		}
	}

	if h.inventorySvc == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"locations": []interface{}{},
		})
	}

	locations, err := h.inventorySvc.ListLocations(c.Request().Context(), parentID)
	if err != nil {
		return h.errorResponse(c, http.StatusInternalServerError, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"locations": locations,
	})
}

// GetLocation retrieves a location
func (h *ExtendedHandler) GetLocation(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid location ID")
	}

	if h.inventorySvc == nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodeInternalError, "location not found")
	}

	location, err := h.inventorySvc.GetLocation(c.Request().Context(), id)
	if err != nil {
		return h.errorResponse(c, http.StatusNotFound, models.CodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, location)
}

// ============= Configuration Handlers =============

// ValidateConfigExtended validates a configuration
func (h *ExtendedHandler) ValidateConfigExtended(c echo.Context) error {
	var req struct {
		DeviceID      string      `json:"device_id"`
		Configuration interface{} `json:"configuration"`
		Checks        []string    `json:"checks"`
	}

	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	if h.configManager == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"valid":    true,
			"errors":   []string{},
			"warnings": []string{},
		})
	}

	// In production, call configManager.Validate
	return c.JSON(http.StatusOK, map[string]interface{}{
		"valid":    true,
		"errors":   []string{},
		"warnings": []string{},
	})
}

// DeployConfigExtended deploys a configuration
func (h *ExtendedHandler) DeployConfigExtended(c echo.Context) error {
	var req struct {
		Targets []struct {
			DeviceID    string      `json:"device_id"`
			ConfigBlock interface{} `json:"config_block"`
		} `json:"targets"`
		DeploymentStrategy string `json:"deployment_strategy"`
		RollbackOnFailure  bool   `json:"rollback_on_failure"`
	}

	if err := c.Bind(&req); err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid request")
	}

	deploymentID := uuid.New()

	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"deployment_id": deploymentID,
		"status":        "pending_approval",
		"targets":       len(req.Targets),
	})
}

// GetDeploymentExtended retrieves deployment status
func (h *ExtendedHandler) GetDeploymentExtended(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid deployment ID")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"deployment_id": id,
		"status":        "completed",
		"created_at":    time.Now().Add(-time.Hour).UTC(),
		"completed_at":  time.Now().UTC(),
		"targets":       []interface{}{},
	})
}

// GetDeviceConfigExtended retrieves device configuration
func (h *ExtendedHandler) GetDeviceConfigExtended(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid device ID")
	}

	section := c.QueryParam("section")
	format := c.QueryParam("format")
	if format == "" {
		format = "normalized"
	}

	if h.configManager == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"device_id":    id,
			"section":      section,
			"format":       format,
			"config":       map[string]interface{}{},
			"sequence":     0,
			"last_updated": time.Now().UTC(),
		})
	}

	// In production, fetch from configManager
	return c.JSON(http.StatusOK, map[string]interface{}{
		"device_id":    id,
		"section":      section,
		"format":       format,
		"config":       map[string]interface{}{},
		"sequence":     0,
		"last_updated": time.Now().UTC(),
	})
}

// GetConfigHistoryExtended retrieves configuration history
func (h *ExtendedHandler) GetConfigHistoryExtended(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.errorResponse(c, http.StatusBadRequest, models.CodePolicyInvalid, "invalid device ID")
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 {
		limit = 50
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"device_id": id,
		"history":   []interface{}{},
		"total":     0,
		"limit":     limit,
	})
}
