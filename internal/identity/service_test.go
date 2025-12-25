package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/zt-nms/zt-nms/internal/identity"
	"github.com/zt-nms/zt-nms/pkg/models"
)

// MockRepository is a mock implementation of identity.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Create(ctx context.Context, identity *models.Identity) error {
	args := m.Called(ctx, identity)
	return args.Error(0)
}

func (m *MockRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Identity), args.Error(1)
}

func (m *MockRepository) GetByPublicKey(ctx context.Context, publicKey ed25519.PublicKey) (*models.Identity, error) {
	args := m.Called(ctx, publicKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Identity), args.Error(1)
}

func (m *MockRepository) GetByUsername(ctx context.Context, username string) (*models.Identity, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Identity), args.Error(1)
}

func (m *MockRepository) Update(ctx context.Context, identity *models.Identity) error {
	args := m.Called(ctx, identity)
	return args.Error(0)
}

func (m *MockRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.IdentityStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) List(ctx context.Context, filter identity.IdentityFilter, limit, offset int) ([]*models.Identity, int, error) {
	args := m.Called(ctx, filter, limit, offset)
	return args.Get(0).([]*models.Identity), args.Int(1), args.Error(2)
}

func (m *MockRepository) GetByGroup(ctx context.Context, group string) ([]*models.Identity, error) {
	args := m.Called(ctx, group)
	return args.Get(0).([]*models.Identity), args.Error(1)
}

// MockAuditLogger is a mock implementation of identity.AuditLogger
type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) LogIdentityEvent(ctx context.Context, eventType models.AuditEventType, identity *models.Identity, actor *uuid.UUID, result models.AuditResult, details map[string]interface{}) error {
	args := m.Called(ctx, eventType, identity, actor, result, details)
	return args.Error(0)
}

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func TestCreateOperator(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)

	service, err := identity.NewService(mockRepo, nil, logger, mockAudit)
	require.NoError(t, err)

	pubKey, _ := generateKeyPair()
	attrs := models.OperatorAttributes{
		Username: "testuser",
		Email:    "test@example.com",
		Groups:   []string{"network-admins"},
	}

	// Mock repository calls
	mockRepo.On("GetByUsername", ctx, "testuser").Return(nil, models.ErrIdentityNotFound)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.Identity")).Return(nil)
	mockAudit.On("LogIdentityEvent", ctx, models.AuditEventIdentityCreate, mock.Anything, mock.Anything, models.AuditResultSuccess, mock.Anything).Return(nil)

	// Execute
	identity, err := service.CreateOperator(ctx, attrs, pubKey, nil)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, identity)
	assert.Equal(t, models.IdentityTypeOperator, identity.Type)
	assert.Equal(t, models.IdentityStatusActive, identity.Status)
	assert.Equal(t, pubKey, identity.PublicKey)

	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestCreateOperator_DuplicateUsername(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	service, err := identity.NewService(mockRepo, nil, logger, nil)
	require.NoError(t, err)

	pubKey, _ := generateKeyPair()
	attrs := models.OperatorAttributes{
		Username: "existinguser",
		Email:    "test@example.com",
	}

	existingIdentity := &models.Identity{
		ID:   uuid.New(),
		Type: models.IdentityTypeOperator,
	}

	mockRepo.On("GetByUsername", ctx, "existinguser").Return(existingIdentity, nil)

	// Execute
	identity, err := service.CreateOperator(ctx, attrs, pubKey, nil)

	// Verify
	assert.Error(t, err)
	assert.Equal(t, models.ErrIdentityExists, err)
	assert.Nil(t, identity)

	mockRepo.AssertExpectations(t)
}

func TestCreateOperator_MissingUsername(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	service, err := identity.NewService(mockRepo, nil, logger, nil)
	require.NoError(t, err)

	pubKey, _ := generateKeyPair()
	attrs := models.OperatorAttributes{
		Email: "test@example.com",
	}

	// Execute
	identity, err := service.CreateOperator(ctx, attrs, pubKey, nil)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, identity)
}

func TestAuthenticate_Success(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)

	service, err := identity.NewService(mockRepo, nil, logger, mockAudit)
	require.NoError(t, err)

	pubKey, privKey := generateKeyPair()
	challenge := []byte("test-challenge-12345")
	signature := ed25519.Sign(privKey, challenge)

	testIdentity := &models.Identity{
		ID:        uuid.New(),
		Type:      models.IdentityTypeOperator,
		PublicKey: pubKey,
		Status:    models.IdentityStatusActive,
	}

	mockRepo.On("GetByPublicKey", ctx, pubKey).Return(testIdentity, nil)
	mockAudit.On("LogIdentityEvent", ctx, models.AuditEventIdentityAuth, testIdentity, mock.Anything, models.AuditResultSuccess, mock.Anything).Return(nil)

	// Execute
	result, err := service.Authenticate(ctx, pubKey, challenge, signature)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, testIdentity.ID, result.ID)

	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestAuthenticate_InvalidSignature(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)

	service, err := identity.NewService(mockRepo, nil, logger, mockAudit)
	require.NoError(t, err)

	pubKey, _ := generateKeyPair()
	_, otherPrivKey := generateKeyPair()
	challenge := []byte("test-challenge-12345")
	signature := ed25519.Sign(otherPrivKey, challenge) // Wrong key

	testIdentity := &models.Identity{
		ID:        uuid.New(),
		Type:      models.IdentityTypeOperator,
		PublicKey: pubKey,
		Status:    models.IdentityStatusActive,
	}

	mockRepo.On("GetByPublicKey", ctx, pubKey).Return(testIdentity, nil)
	mockAudit.On("LogIdentityEvent", ctx, models.AuditEventIdentityAuthFailed, testIdentity, mock.Anything, models.AuditResultFailure, mock.Anything).Return(nil)

	// Execute
	result, err := service.Authenticate(ctx, pubKey, challenge, signature)

	// Verify
	assert.Error(t, err)
	assert.Equal(t, models.ErrAuthenticationFailed, err)
	assert.Nil(t, result)

	mockRepo.AssertExpectations(t)
}

func TestAuthenticate_SuspendedIdentity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)

	service, err := identity.NewService(mockRepo, nil, logger, mockAudit)
	require.NoError(t, err)

	pubKey, privKey := generateKeyPair()
	challenge := []byte("test-challenge-12345")
	signature := ed25519.Sign(privKey, challenge)

	testIdentity := &models.Identity{
		ID:        uuid.New(),
		Type:      models.IdentityTypeOperator,
		PublicKey: pubKey,
		Status:    models.IdentityStatusSuspended,
	}

	mockRepo.On("GetByPublicKey", ctx, pubKey).Return(testIdentity, nil)
	mockAudit.On("LogIdentityEvent", ctx, models.AuditEventIdentityAuthFailed, testIdentity, mock.Anything, models.AuditResultFailure, mock.Anything).Return(nil)

	// Execute
	result, err := service.Authenticate(ctx, pubKey, challenge, signature)

	// Verify
	assert.Error(t, err)
	assert.Equal(t, models.ErrIdentitySuspended, err)
	assert.Nil(t, result)
}

func TestSuspendIdentity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)

	service, err := identity.NewService(mockRepo, nil, logger, mockAudit)
	require.NoError(t, err)

	identityID := uuid.New()
	suspendedBy := uuid.New()

	testIdentity := &models.Identity{
		ID:     identityID,
		Status: models.IdentityStatusActive,
	}

	mockRepo.On("GetByID", ctx, identityID).Return(testIdentity, nil)
	mockRepo.On("UpdateStatus", ctx, identityID, models.IdentityStatusSuspended).Return(nil)
	mockAudit.On("LogIdentityEvent", ctx, models.AuditEventIdentityUpdate, testIdentity, &suspendedBy, models.AuditResultSuccess, mock.Anything).Return(nil)

	// Execute
	err = service.Suspend(ctx, identityID, suspendedBy, "security concern")

	// Verify
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestRevokeIdentity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)

	service, err := identity.NewService(mockRepo, nil, logger, mockAudit)
	require.NoError(t, err)

	identityID := uuid.New()
	revokedBy := uuid.New()

	testIdentity := &models.Identity{
		ID:     identityID,
		Status: models.IdentityStatusActive,
	}

	mockRepo.On("GetByID", ctx, identityID).Return(testIdentity, nil)
	mockRepo.On("UpdateStatus", ctx, identityID, models.IdentityStatusRevoked).Return(nil)
	mockAudit.On("LogIdentityEvent", ctx, models.AuditEventIdentityUpdate, testIdentity, &revokedBy, models.AuditResultSuccess, mock.Anything).Return(nil)

	// Execute
	err = service.Revoke(ctx, identityID, revokedBy, "terminated")

	// Verify
	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestListIdentities(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	service, err := identity.NewService(mockRepo, nil, logger, nil)
	require.NoError(t, err)

	filter := identity.IdentityFilter{
		Type:   models.IdentityTypeOperator,
		Status: models.IdentityStatusActive,
	}

	expectedIdentities := []*models.Identity{
		{ID: uuid.New(), Type: models.IdentityTypeOperator},
		{ID: uuid.New(), Type: models.IdentityTypeOperator},
	}

	mockRepo.On("List", ctx, filter, 50, 0).Return(expectedIdentities, 2, nil)

	// Execute
	identities, total, err := service.List(ctx, filter, 0, 0)

	// Verify
	assert.NoError(t, err)
	assert.Len(t, identities, 2)
	assert.Equal(t, 2, total)

	mockRepo.AssertExpectations(t)
}

func TestCreateDevice(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)

	service, err := identity.NewService(mockRepo, nil, logger, mockAudit)
	require.NoError(t, err)

	pubKey, _ := generateKeyPair()
	attrs := models.DeviceAttributes{
		Hostname:     "router-01",
		ManagementIP: "10.0.0.1",
		Vendor:       "Cisco",
		Model:        "ISR 4431",
	}

	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.Identity")).Return(nil)
	mockAudit.On("LogIdentityEvent", ctx, models.AuditEventIdentityCreate, mock.Anything, mock.Anything, models.AuditResultSuccess, mock.Anything).Return(nil)

	// Execute
	identity, err := service.CreateDevice(ctx, attrs, pubKey, nil)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, identity)
	assert.Equal(t, models.IdentityTypeDevice, identity.Type)
	assert.Equal(t, models.IdentityStatusActive, identity.Status)

	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

// Benchmark tests
func BenchmarkAuthenticate(b *testing.B) {
	ctx := context.Background()
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	service, _ := identity.NewService(mockRepo, nil, logger, nil)

	pubKey, privKey := generateKeyPair()
	challenge := []byte("benchmark-challenge-12345")
	signature := ed25519.Sign(privKey, challenge)

	testIdentity := &models.Identity{
		ID:        uuid.New(),
		Type:      models.IdentityTypeOperator,
		PublicKey: pubKey,
		Status:    models.IdentityStatusActive,
	}

	mockRepo.On("GetByPublicKey", ctx, pubKey).Return(testIdentity, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.Authenticate(ctx, pubKey, challenge, signature)
	}
}
