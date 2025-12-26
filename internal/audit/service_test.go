package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/zt-nms/zt-nms/internal/audit"
	"github.com/zt-nms/zt-nms/pkg/models"
)

// MockRepository is a mock implementation of audit.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Append(ctx context.Context, event *models.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditEvent, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditEvent), args.Error(1)
}

func (m *MockRepository) Query(ctx context.Context, filter audit.AuditFilter) ([]*models.AuditEvent, int, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*models.AuditEvent), args.Int(1), args.Error(2)
}

func (m *MockRepository) GetLastHash(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func createTestEvent() *models.AuditEvent {
	return &models.AuditEvent{
		ID:           uuid.New(),
		Timestamp:    time.Now().UTC(),
		Type:         models.AuditEventIdentityAuth,
		ActorID:      uuid.New(),
		ResourceType: "identity",
		ResourceID:   uuid.New().String(),
		Action:       "authenticate",
		Result:       models.AuditResultSuccess,
		Details:      map[string]interface{}{"method": "ed25519"},
	}
}

func TestNewService(t *testing.T) {
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	// Mock GetLastHash for initialization
	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)

	service, err := audit.NewService(mockRepo, logger)

	require.NoError(t, err)
	assert.NotNil(t, service)
}

func TestLog(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)
	mockRepo.On("Append", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	event := createTestEvent()
	err = service.Log(ctx, event)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestLogWithPreviousHash(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	previousHash := "abc123def456"
	mockRepo.On("GetLastHash", mock.Anything).Return(previousHash, nil)
	mockRepo.On("Append", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	event := createTestEvent()
	err = service.Log(ctx, event)

	assert.NoError(t, err)
	assert.Equal(t, previousHash, event.PreviousHash)
	mockRepo.AssertExpectations(t)
}

func TestQuery(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	filter := audit.AuditFilter{
		EventTypes: []models.AuditEventType{models.AuditEventIdentityAuth},
		Limit:      50,
		Offset:     0,
	}

	expectedEvents := []*models.AuditEvent{
		createTestEvent(),
		createTestEvent(),
	}

	mockRepo.On("Query", ctx, filter).Return(expectedEvents, 2, nil)

	events, total, err := service.Query(ctx, filter)

	assert.NoError(t, err)
	assert.Len(t, events, 2)
	assert.Equal(t, 2, total)
	mockRepo.AssertExpectations(t)
}

func TestQueryByActor(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	actorID := uuid.New()
	filter := audit.AuditFilter{
		ActorID: &actorID,
		Limit:   50,
		Offset:  0,
	}

	expectedEvents := []*models.AuditEvent{
		createTestEvent(),
	}

	mockRepo.On("Query", ctx, filter).Return(expectedEvents, 1, nil)

	events, total, err := service.Query(ctx, filter)

	assert.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, 1, total)
	mockRepo.AssertExpectations(t)
}

func TestQueryByTimeRange(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()
	filter := audit.AuditFilter{
		StartTime: &start,
		EndTime:   &end,
		Limit:     100,
		Offset:    0,
	}

	expectedEvents := []*models.AuditEvent{
		createTestEvent(),
		createTestEvent(),
		createTestEvent(),
	}

	mockRepo.On("Query", ctx, filter).Return(expectedEvents, 3, nil)

	events, total, err := service.Query(ctx, filter)

	assert.NoError(t, err)
	assert.Len(t, events, 3)
	assert.Equal(t, 3, total)
	mockRepo.AssertExpectations(t)
}

func TestGetByID(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	eventID := uuid.New()
	expectedEvent := createTestEvent()
	expectedEvent.ID = eventID

	mockRepo.On("GetByID", ctx, eventID).Return(expectedEvent, nil)

	event, err := service.GetByID(ctx, eventID)

	assert.NoError(t, err)
	assert.NotNil(t, event)
	assert.Equal(t, eventID, event.ID)
	mockRepo.AssertExpectations(t)
}

func TestVerifyChain(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	filter := audit.AuditFilter{
		Limit:  1000,
		Offset: 0,
	}

	// Create a chain of events
	event1 := createTestEvent()
	event1.PreviousHash = ""
	event1.Hash = "hash1"

	event2 := createTestEvent()
	event2.PreviousHash = "hash1"
	event2.Hash = "hash2"

	events := []*models.AuditEvent{event1, event2}

	mockRepo.On("Query", ctx, filter).Return(events, 2, nil)

	valid, err := service.VerifyChain(ctx, filter)

	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestLogIdentityEvent(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)
	mockRepo.On("Append", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	identity := &models.Identity{
		ID:   uuid.New(),
		Type: models.IdentityTypeOperator,
	}
	actorID := uuid.New()

	err = service.LogIdentityEvent(ctx, models.AuditEventIdentityCreate, identity, &actorID, models.AuditResultSuccess, nil)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestLogPolicyEvent(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)
	mockRepo.On("Append", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	policy := &models.Policy{
		ID:   uuid.New(),
		Name: "test-policy",
	}
	actorID := uuid.New()

	err = service.LogPolicyEvent(ctx, models.AuditEventPolicyCreate, policy, &actorID, models.AuditResultSuccess, nil)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestLogConfigEvent(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)
	mockRepo.On("Append", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	service, err := audit.NewService(mockRepo, logger)
	require.NoError(t, err)

	deviceID := uuid.New()
	actorID := uuid.New()

	err = service.LogConfigEvent(ctx, models.AuditEventConfigDeploy, deviceID, &actorID, models.AuditResultSuccess, map[string]interface{}{
		"version": 1,
	})

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

// Benchmark tests
func BenchmarkLog(b *testing.B) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)
	mockRepo.On("Append", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	service, _ := audit.NewService(mockRepo, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := createTestEvent()
		service.Log(ctx, event)
	}
}

func BenchmarkQuery(b *testing.B) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	mockRepo.On("GetLastHash", mock.Anything).Return("", nil)

	service, _ := audit.NewService(mockRepo, logger)

	filter := audit.AuditFilter{
		Limit:  50,
		Offset: 0,
	}

	events := []*models.AuditEvent{createTestEvent()}
	mockRepo.On("Query", ctx, filter).Return(events, 1, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.Query(ctx, filter)
	}
}
