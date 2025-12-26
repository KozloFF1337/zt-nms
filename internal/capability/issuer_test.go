package capability_test

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

	"github.com/zt-nms/zt-nms/internal/capability"
	"github.com/zt-nms/zt-nms/pkg/models"
)

// MockRepository implements capability.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Create(ctx context.Context, token *models.CapabilityToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.CapabilityToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.CapabilityToken), args.Error(1)
}

func (m *MockRepository) Update(ctx context.Context, token *models.CapabilityToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) List(ctx context.Context, filter capability.TokenFilter) ([]*models.CapabilityToken, int, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*models.CapabilityToken), args.Int(1), args.Error(2)
}

func (m *MockRepository) ListBySubject(ctx context.Context, subjectID uuid.UUID) ([]*models.CapabilityToken, error) {
	args := m.Called(ctx, subjectID)
	return args.Get(0).([]*models.CapabilityToken), args.Error(1)
}

func (m *MockRepository) CleanupExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// MockPolicyEngine implements capability.PolicyEngine
type MockPolicyEngine struct {
	mock.Mock
}

func (m *MockPolicyEngine) Evaluate(ctx context.Context, req models.PolicyEvaluationRequest) (*models.PolicyDecision, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*models.PolicyDecision), args.Error(1)
}

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func createTestToken() *models.CapabilityToken {
	return &models.CapabilityToken{
		ID:        uuid.New(),
		SubjectID: uuid.New(),
		Resource: models.ResourceRef{
			Type: "device",
			ID:   "device-123",
		},
		Actions:   []string{"read", "write"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Status:    models.TokenStatusActive,
	}
}

func TestNewIssuer(t *testing.T) {
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:      "test-issuer",
		DefaultTTL:    time.Hour,
		MaxTTL:        24 * time.Hour,
		CleanupPeriod: time.Minute,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)

	require.NoError(t, err)
	assert.NotNil(t, issuer)
}

func TestIssue(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	subjectID := uuid.New()
	resource := models.ResourceRef{Type: "device", ID: "device-123"}
	actions := []string{"read", "write"}

	// Mock policy evaluation - allow
	mockPolicy.On("Evaluate", ctx, mock.AnythingOfType("models.PolicyEvaluationRequest")).Return(&models.PolicyDecision{
		Decision: models.PolicyEffectAllow,
	}, nil)

	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.CapabilityToken")).Return(nil)

	token, err := issuer.Issue(ctx, subjectID, resource, actions, time.Hour, "Test capability")

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, subjectID, token.SubjectID)
	assert.Equal(t, resource.Type, token.Resource.Type)
	assert.Equal(t, resource.ID, token.Resource.ID)
	assert.Equal(t, actions, token.Actions)
	assert.Equal(t, models.TokenStatusActive, token.Status)
	mockRepo.AssertExpectations(t)
	mockPolicy.AssertExpectations(t)
}

func TestIssue_PolicyDenied(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	subjectID := uuid.New()
	resource := models.ResourceRef{Type: "device", ID: "device-123"}
	actions := []string{"admin"}

	// Mock policy evaluation - deny
	mockPolicy.On("Evaluate", ctx, mock.AnythingOfType("models.PolicyEvaluationRequest")).Return(&models.PolicyDecision{
		Decision: models.PolicyEffectDeny,
		Reason:   "Access denied by policy",
	}, nil)

	token, err := issuer.Issue(ctx, subjectID, resource, actions, time.Hour, "Test capability")

	assert.Error(t, err)
	assert.Nil(t, token)
	mockPolicy.AssertExpectations(t)
}

func TestIssue_ExceedsMaxTTL(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	subjectID := uuid.New()
	resource := models.ResourceRef{Type: "device", ID: "device-123"}
	actions := []string{"read"}

	// Mock policy evaluation - allow
	mockPolicy.On("Evaluate", ctx, mock.AnythingOfType("models.PolicyEvaluationRequest")).Return(&models.PolicyDecision{
		Decision: models.PolicyEffectAllow,
	}, nil)

	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.CapabilityToken")).Return(nil)

	// Request 48 hours, but max is 24 hours
	token, err := issuer.Issue(ctx, subjectID, resource, actions, 48*time.Hour, "Test capability")

	assert.NoError(t, err)
	assert.NotNil(t, token)
	// TTL should be capped at MaxTTL
	expectedExpiry := token.IssuedAt.Add(24 * time.Hour)
	assert.True(t, token.ExpiresAt.Before(expectedExpiry.Add(time.Second)) && token.ExpiresAt.After(expectedExpiry.Add(-time.Second)))
}

func TestValidate_ValidToken(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	tokenID := uuid.New()
	testToken := &models.CapabilityToken{
		ID:        tokenID,
		SubjectID: uuid.New(),
		Resource:  models.ResourceRef{Type: "device", ID: "device-123"},
		Actions:   []string{"read"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Status:    models.TokenStatusActive,
	}

	mockRepo.On("GetByID", ctx, tokenID).Return(testToken, nil)

	valid, err := issuer.Validate(ctx, tokenID, "device", "device-123", "read")

	assert.NoError(t, err)
	assert.True(t, valid)
	mockRepo.AssertExpectations(t)
}

func TestValidate_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	tokenID := uuid.New()
	testToken := &models.CapabilityToken{
		ID:        tokenID,
		SubjectID: uuid.New(),
		Resource:  models.ResourceRef{Type: "device", ID: "device-123"},
		Actions:   []string{"read"},
		IssuedAt:  time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-time.Hour), // Expired
		Status:    models.TokenStatusActive,
	}

	mockRepo.On("GetByID", ctx, tokenID).Return(testToken, nil)

	valid, err := issuer.Validate(ctx, tokenID, "device", "device-123", "read")

	assert.NoError(t, err)
	assert.False(t, valid)
	mockRepo.AssertExpectations(t)
}

func TestValidate_RevokedToken(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	tokenID := uuid.New()
	testToken := &models.CapabilityToken{
		ID:        tokenID,
		SubjectID: uuid.New(),
		Resource:  models.ResourceRef{Type: "device", ID: "device-123"},
		Actions:   []string{"read"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Status:    models.TokenStatusRevoked, // Revoked
	}

	mockRepo.On("GetByID", ctx, tokenID).Return(testToken, nil)

	valid, err := issuer.Validate(ctx, tokenID, "device", "device-123", "read")

	assert.NoError(t, err)
	assert.False(t, valid)
	mockRepo.AssertExpectations(t)
}

func TestValidate_WrongAction(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	tokenID := uuid.New()
	testToken := &models.CapabilityToken{
		ID:        tokenID,
		SubjectID: uuid.New(),
		Resource:  models.ResourceRef{Type: "device", ID: "device-123"},
		Actions:   []string{"read"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Status:    models.TokenStatusActive,
	}

	mockRepo.On("GetByID", ctx, tokenID).Return(testToken, nil)

	valid, err := issuer.Validate(ctx, tokenID, "device", "device-123", "write") // Wrong action

	assert.NoError(t, err)
	assert.False(t, valid)
	mockRepo.AssertExpectations(t)
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	tokenID := uuid.New()

	mockRepo.On("Revoke", ctx, tokenID).Return(nil)

	err = issuer.Revoke(ctx, tokenID, "Security concern")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestListBySubject(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	subjectID := uuid.New()
	expectedTokens := []*models.CapabilityToken{
		createTestToken(),
		createTestToken(),
	}

	mockRepo.On("ListBySubject", ctx, subjectID).Return(expectedTokens, nil)

	tokens, err := issuer.ListBySubject(ctx, subjectID)

	assert.NoError(t, err)
	assert.Len(t, tokens, 2)
	mockRepo.AssertExpectations(t)
}

func TestDelegate(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	parentID := uuid.New()
	delegateeID := uuid.New()

	parentToken := &models.CapabilityToken{
		ID:        parentID,
		SubjectID: uuid.New(),
		Resource:  models.ResourceRef{Type: "device", ID: "device-123"},
		Actions:   []string{"read", "write"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Status:    models.TokenStatusActive,
		Delegable: true,
	}

	mockRepo.On("GetByID", ctx, parentID).Return(parentToken, nil)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*models.CapabilityToken")).Return(nil)

	delegatedToken, err := issuer.Delegate(ctx, parentID, delegateeID, []string{"read"}, 30*time.Minute)

	assert.NoError(t, err)
	assert.NotNil(t, delegatedToken)
	assert.Equal(t, delegateeID, delegatedToken.SubjectID)
	assert.Equal(t, []string{"read"}, delegatedToken.Actions)
	assert.Equal(t, parentID, *delegatedToken.ParentID)
	mockRepo.AssertExpectations(t)
}

func TestDelegate_NonDelegable(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, mockPolicy, config, logger)
	require.NoError(t, err)

	parentID := uuid.New()
	delegateeID := uuid.New()

	parentToken := &models.CapabilityToken{
		ID:        parentID,
		SubjectID: uuid.New(),
		Resource:  models.ResourceRef{Type: "device", ID: "device-123"},
		Actions:   []string{"read", "write"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Status:    models.TokenStatusActive,
		Delegable: false, // Not delegable
	}

	mockRepo.On("GetByID", ctx, parentID).Return(parentToken, nil)

	delegatedToken, err := issuer.Delegate(ctx, parentID, delegateeID, []string{"read"}, 30*time.Minute)

	assert.Error(t, err)
	assert.Nil(t, delegatedToken)
}

// Benchmark tests
func BenchmarkValidate(b *testing.B) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockPolicy := new(MockPolicyEngine)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, _ := capability.NewIssuer(mockRepo, mockPolicy, config, logger)

	tokenID := uuid.New()
	testToken := &models.CapabilityToken{
		ID:        tokenID,
		SubjectID: uuid.New(),
		Resource:  models.ResourceRef{Type: "device", ID: "device-123"},
		Actions:   []string{"read"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Status:    models.TokenStatusActive,
	}

	mockRepo.On("GetByID", ctx, tokenID).Return(testToken, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		issuer.Validate(ctx, tokenID, "device", "device-123", "read")
	}
}
