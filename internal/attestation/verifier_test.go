package attestation_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/zt-nms/zt-nms/internal/attestation"
	"github.com/zt-nms/zt-nms/pkg/models"
)

// MockRepository implements attestation.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Create(ctx context.Context, result *models.AttestationResult) error {
	args := m.Called(ctx, result)
	return args.Error(0)
}

func (m *MockRepository) GetByDevice(ctx context.Context, deviceID uuid.UUID) ([]*models.AttestationResult, error) {
	args := m.Called(ctx, deviceID)
	return args.Get(0).([]*models.AttestationResult), args.Error(1)
}

func (m *MockRepository) GetLatest(ctx context.Context, deviceID uuid.UUID) (*models.AttestationResult, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AttestationResult), args.Error(1)
}

func (m *MockRepository) GetExpected(ctx context.Context, deviceID uuid.UUID) (*models.ExpectedMeasurement, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ExpectedMeasurement), args.Error(1)
}

func (m *MockRepository) SetExpected(ctx context.Context, expected *models.ExpectedMeasurement) error {
	args := m.Called(ctx, expected)
	return args.Error(0)
}

// MockAuditLogger implements attestation.AuditLogger
type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) LogAttestationEvent(ctx context.Context, eventType models.AuditEventType, deviceID uuid.UUID, result models.AuditResult, details map[string]interface{}) error {
	args := m.Called(ctx, eventType, deviceID, result, details)
	return args.Error(0)
}

func createTestMeasurement() models.DeviceMeasurement {
	return models.DeviceMeasurement{
		FirmwareHash:   "abc123",
		ConfigHash:     "def456",
		BootHash:       "ghi789",
		SoftwareHashes: map[string]string{"os": "os-hash", "app": "app-hash"},
		Timestamp:      time.Now().UTC(),
	}
}

func createTestExpected() *models.ExpectedMeasurement {
	return &models.ExpectedMeasurement{
		ID:             uuid.New(),
		DeviceID:       uuid.New(),
		FirmwareHash:   "abc123",
		ConfigHash:     "def456",
		BootHash:       "ghi789",
		SoftwareHashes: map[string]string{"os": "os-hash", "app": "app-hash"},
		ValidFrom:      time.Now().UTC().Add(-time.Hour),
		SetBy:          uuid.New(),
	}
}

func TestNewVerifier(t *testing.T) {
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		AllowUnknown:     false,
		RequireAll:       true,
		CacheExpiry:      time.Minute,
		MaxAgeTolerance:  time.Hour,
		AlertOnMismatch:  true,
		QuarantineAction: true,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)

	require.NoError(t, err)
	assert.NotNil(t, verifier)
}

func TestVerify_Success(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		AllowUnknown:    false,
		RequireAll:      true,
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	measurement := createTestMeasurement()
	expected := createTestExpected()
	expected.DeviceID = deviceID

	mockRepo.On("GetExpected", ctx, deviceID).Return(expected, nil)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.AttestationResult")).Return(nil)
	mockAudit.On("LogAttestationEvent", ctx, models.AuditEventAttestationSuccess, deviceID, models.AuditResultSuccess, mock.Anything).Return(nil)

	result, err := verifier.Verify(ctx, deviceID, measurement)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Verified)
	assert.Equal(t, models.TrustStatusVerified, result.TrustStatus)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestVerify_Mismatch(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		AllowUnknown:     false,
		RequireAll:       true,
		CacheExpiry:      time.Minute,
		MaxAgeTolerance:  time.Hour,
		AlertOnMismatch:  true,
		QuarantineAction: true,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	measurement := createTestMeasurement()
	measurement.FirmwareHash = "different-hash" // Mismatch

	expected := createTestExpected()
	expected.DeviceID = deviceID

	mockRepo.On("GetExpected", ctx, deviceID).Return(expected, nil)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.AttestationResult")).Return(nil)
	mockAudit.On("LogAttestationEvent", ctx, models.AuditEventAttestationFailed, deviceID, models.AuditResultFailure, mock.Anything).Return(nil)

	result, err := verifier.Verify(ctx, deviceID, measurement)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Verified)
	assert.Contains(t, result.TrustStatus, models.TrustStatusCompromised)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestVerify_NoExpected(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		AllowUnknown:    false, // Don't allow unknown
		RequireAll:      true,
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	measurement := createTestMeasurement()

	mockRepo.On("GetExpected", ctx, deviceID).Return(nil, models.ErrNotFound)

	result, err := verifier.Verify(ctx, deviceID, measurement)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestVerify_AllowUnknown(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		AllowUnknown:    true, // Allow unknown
		RequireAll:      true,
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	measurement := createTestMeasurement()

	mockRepo.On("GetExpected", ctx, deviceID).Return(nil, models.ErrNotFound)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.AttestationResult")).Return(nil)
	mockAudit.On("LogAttestationEvent", ctx, models.AuditEventAttestationSuccess, deviceID, models.AuditResultSuccess, mock.Anything).Return(nil)

	result, err := verifier.Verify(ctx, deviceID, measurement)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, models.TrustStatusUnknown, result.TrustStatus)
}

func TestSetExpected(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	setBy := uuid.New()
	measurement := createTestMeasurement()

	mockRepo.On("SetExpected", ctx, mock.AnythingOfType("*models.ExpectedMeasurement")).Return(nil)

	err = verifier.SetExpected(ctx, deviceID, measurement, setBy)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestGetLatest(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	expectedResult := &models.AttestationResult{
		ID:          uuid.New(),
		DeviceID:    deviceID,
		Verified:    true,
		TrustStatus: models.TrustStatusVerified,
		VerifiedAt:  time.Now().UTC(),
	}

	mockRepo.On("GetLatest", ctx, deviceID).Return(expectedResult, nil)

	result, err := verifier.GetLatest(ctx, deviceID)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, deviceID, result.DeviceID)
	assert.True(t, result.Verified)
	mockRepo.AssertExpectations(t)
}

func TestGetHistory(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	expectedResults := []*models.AttestationResult{
		{ID: uuid.New(), DeviceID: deviceID, Verified: true},
		{ID: uuid.New(), DeviceID: deviceID, Verified: false},
	}

	mockRepo.On("GetByDevice", ctx, deviceID).Return(expectedResults, nil)

	results, err := verifier.GetHistory(ctx, deviceID)

	assert.NoError(t, err)
	assert.Len(t, results, 2)
	mockRepo.AssertExpectations(t)
}

func TestVerify_ExpiredMeasurement(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		AllowUnknown:    false,
		RequireAll:      true,
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Minute, // Very short tolerance
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	measurement := createTestMeasurement()
	measurement.Timestamp = time.Now().UTC().Add(-time.Hour) // Old measurement

	expected := createTestExpected()
	expected.DeviceID = deviceID

	mockRepo.On("GetExpected", ctx, deviceID).Return(expected, nil)

	result, err := verifier.Verify(ctx, deviceID, measurement)

	// Should fail due to old measurement
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestCompare(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	expected := createTestExpected()
	measurement := createTestMeasurement()

	comparison := verifier.Compare(expected, measurement)

	assert.NotNil(t, comparison)
	assert.True(t, comparison.FirmwareMatch)
	assert.True(t, comparison.ConfigMatch)
	assert.True(t, comparison.BootMatch)
	assert.True(t, comparison.AllMatch)
}

func TestCompare_Mismatch(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, err := attestation.NewVerifier(mockRepo, mockAudit, config, logger)
	require.NoError(t, err)

	expected := createTestExpected()
	measurement := createTestMeasurement()
	measurement.FirmwareHash = "different-hash"

	comparison := verifier.Compare(expected, measurement)

	assert.NotNil(t, comparison)
	assert.False(t, comparison.FirmwareMatch)
	assert.True(t, comparison.ConfigMatch)
	assert.True(t, comparison.BootMatch)
	assert.False(t, comparison.AllMatch)
}

// Benchmark tests
func BenchmarkVerify(b *testing.B) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		AllowUnknown:    false,
		RequireAll:      true,
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, _ := attestation.NewVerifier(mockRepo, mockAudit, config, logger)

	deviceID := uuid.New()
	measurement := createTestMeasurement()
	expected := createTestExpected()
	expected.DeviceID = deviceID

	mockRepo.On("GetExpected", ctx, deviceID).Return(expected, nil)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.AttestationResult")).Return(nil)
	mockAudit.On("LogAttestationEvent", ctx, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.Verify(ctx, deviceID, measurement)
	}
}

func BenchmarkCompare(b *testing.B) {
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.VerifierConfig{
		CacheExpiry:     time.Minute,
		MaxAgeTolerance: time.Hour,
	}

	verifier, _ := attestation.NewVerifier(mockRepo, mockAudit, config, logger)

	expected := createTestExpected()
	measurement := createTestMeasurement()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.Compare(expected, measurement)
	}
}
