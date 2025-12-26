package config_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/zt-nms/zt-nms/internal/config"
	"github.com/zt-nms/zt-nms/pkg/models"
)

// MockRepository implements config.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateBlock(ctx context.Context, block *models.ConfigBlock) error {
	args := m.Called(ctx, block)
	return args.Error(0)
}

func (m *MockRepository) GetBlock(ctx context.Context, id uuid.UUID) (*models.ConfigBlock, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ConfigBlock), args.Error(1)
}

func (m *MockRepository) GetBlocksByDevice(ctx context.Context, deviceID uuid.UUID) ([]*models.ConfigBlock, error) {
	args := m.Called(ctx, deviceID)
	return args.Get(0).([]*models.ConfigBlock), args.Error(1)
}

func (m *MockRepository) GetActiveConfig(ctx context.Context, deviceID uuid.UUID) (*models.ConfigBlock, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ConfigBlock), args.Error(1)
}

func (m *MockRepository) UpdateBlockStatus(ctx context.Context, id uuid.UUID, status models.ConfigStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockRepository) CreateDeployment(ctx context.Context, deployment *models.Deployment) error {
	args := m.Called(ctx, deployment)
	return args.Error(0)
}

func (m *MockRepository) GetDeployment(ctx context.Context, id uuid.UUID) (*models.Deployment, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Deployment), args.Error(1)
}

func (m *MockRepository) UpdateDeployment(ctx context.Context, deployment *models.Deployment) error {
	args := m.Called(ctx, deployment)
	return args.Error(0)
}

func (m *MockRepository) ListDeployments(ctx context.Context, deviceID *uuid.UUID, status *models.DeploymentStatus, limit, offset int) ([]*models.Deployment, int, error) {
	args := m.Called(ctx, deviceID, status, limit, offset)
	return args.Get(0).([]*models.Deployment), args.Int(1), args.Error(2)
}

// MockAuditLogger implements config.AuditLogger
type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) LogConfigEvent(ctx context.Context, eventType models.AuditEventType, deviceID uuid.UUID, actor *uuid.UUID, result models.AuditResult, details map[string]interface{}) error {
	args := m.Called(ctx, eventType, deviceID, actor, result, details)
	return args.Error(0)
}

func createTestBlock() *models.ConfigBlock {
	return &models.ConfigBlock{
		ID:       uuid.New(),
		DeviceID: uuid.New(),
		Content:  "hostname test-router\ninterface GigabitEthernet0/0\n  ip address 10.0.0.1 255.255.255.0",
		Hash:     "abc123def456",
		Sequence: 1,
		Status:   models.ConfigStatusDraft,
	}
}

func TestNewManager(t *testing.T) {
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)
	assert.NotNil(t, manager)
}

func TestCreateBlock(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	deviceID := uuid.New()
	content := "hostname test-router"
	authorID := uuid.New()

	mockRepo.On("CreateBlock", ctx, mock.AnythingOfType("*models.ConfigBlock")).Return(nil)
	mockAudit.On("LogConfigEvent", ctx, models.AuditEventConfigCreate, deviceID, &authorID, models.AuditResultSuccess, mock.Anything).Return(nil)

	block, err := manager.CreateBlock(ctx, deviceID, content, &authorID)

	assert.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, deviceID, block.DeviceID)
	assert.Equal(t, content, block.Content)
	assert.NotEmpty(t, block.Hash)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestGetBlock(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	blockID := uuid.New()
	expectedBlock := createTestBlock()
	expectedBlock.ID = blockID

	mockRepo.On("GetBlock", ctx, blockID).Return(expectedBlock, nil)

	block, err := manager.GetBlock(ctx, blockID)

	assert.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, blockID, block.ID)
	mockRepo.AssertExpectations(t)
}

func TestGetBlocksByDevice(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	deviceID := uuid.New()
	expectedBlocks := []*models.ConfigBlock{
		createTestBlock(),
		createTestBlock(),
	}

	mockRepo.On("GetBlocksByDevice", ctx, deviceID).Return(expectedBlocks, nil)

	blocks, err := manager.GetBlocksByDevice(ctx, deviceID)

	assert.NoError(t, err)
	assert.Len(t, blocks, 2)
	mockRepo.AssertExpectations(t)
}

func TestValidateBlock(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	block := createTestBlock()

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)
	mockRepo.On("UpdateBlockStatus", ctx, block.ID, models.ConfigStatusValidated).Return(nil)

	result, err := manager.ValidateBlock(ctx, block.ID)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Valid)
	mockRepo.AssertExpectations(t)
}

func TestDeploy(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	blockID := uuid.New()
	deviceID := uuid.New()
	initiatorID := uuid.New()

	block := createTestBlock()
	block.ID = blockID
	block.DeviceID = deviceID
	block.Status = models.ConfigStatusValidated

	mockRepo.On("GetBlock", ctx, blockID).Return(block, nil)
	mockRepo.On("CreateDeployment", ctx, mock.AnythingOfType("*models.Deployment")).Return(nil)
	mockAudit.On("LogConfigEvent", ctx, models.AuditEventConfigDeploy, deviceID, &initiatorID, models.AuditResultSuccess, mock.Anything).Return(nil)

	deployment, err := manager.Deploy(ctx, blockID, &initiatorID, models.DeploymentStrategyAtomic)

	assert.NoError(t, err)
	assert.NotNil(t, deployment)
	assert.Equal(t, blockID, deployment.ConfigBlockID)
	assert.Equal(t, models.DeploymentStrategyAtomic, deployment.Strategy)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestDeploy_NotValidated(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	blockID := uuid.New()
	initiatorID := uuid.New()

	block := createTestBlock()
	block.ID = blockID
	block.Status = models.ConfigStatusDraft // Not validated

	mockRepo.On("GetBlock", ctx, blockID).Return(block, nil)

	deployment, err := manager.Deploy(ctx, blockID, &initiatorID, models.DeploymentStrategyAtomic)

	assert.Error(t, err)
	assert.Nil(t, deployment)
}

func TestRollback(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	deviceID := uuid.New()
	initiatorID := uuid.New()

	// Previous block
	previousBlock := createTestBlock()
	previousBlock.DeviceID = deviceID
	previousBlock.Sequence = 1
	previousBlock.Status = models.ConfigStatusDeployed

	mockRepo.On("GetBlocksByDevice", ctx, deviceID).Return([]*models.ConfigBlock{previousBlock}, nil)
	mockRepo.On("CreateDeployment", ctx, mock.AnythingOfType("*models.Deployment")).Return(nil)
	mockAudit.On("LogConfigEvent", ctx, models.AuditEventConfigRollback, deviceID, &initiatorID, models.AuditResultSuccess, mock.Anything).Return(nil)

	err := manager.Rollback(ctx, deviceID, 1, &initiatorID)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestGetDeployment(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	deploymentID := uuid.New()
	expectedDeployment := &models.Deployment{
		ID:            deploymentID,
		ConfigBlockID: uuid.New(),
		Status:        models.DeploymentStatusCompleted,
		Strategy:      models.DeploymentStrategyAtomic,
		StartedAt:     time.Now().UTC(),
	}

	mockRepo.On("GetDeployment", ctx, deploymentID).Return(expectedDeployment, nil)

	deployment, err := manager.GetDeployment(ctx, deploymentID)

	assert.NoError(t, err)
	assert.NotNil(t, deployment)
	assert.Equal(t, deploymentID, deployment.ID)
	mockRepo.AssertExpectations(t)
}

func TestListDeployments(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	expectedDeployments := []*models.Deployment{
		{ID: uuid.New(), Status: models.DeploymentStatusCompleted},
		{ID: uuid.New(), Status: models.DeploymentStatusPending},
	}

	mockRepo.On("ListDeployments", ctx, (*uuid.UUID)(nil), (*models.DeploymentStatus)(nil), 50, 0).Return(expectedDeployments, 2, nil)

	deployments, total, err := manager.ListDeployments(ctx, nil, nil, 50, 0)

	assert.NoError(t, err)
	assert.Len(t, deployments, 2)
	assert.Equal(t, 2, total)
	mockRepo.AssertExpectations(t)
}

func TestCompleteDeployment(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	deploymentID := uuid.New()
	configBlockID := uuid.New()
	deviceID := uuid.New()

	deployment := &models.Deployment{
		ID:            deploymentID,
		ConfigBlockID: configBlockID,
		Status:        models.DeploymentStatusInProgress,
	}

	block := createTestBlock()
	block.ID = configBlockID
	block.DeviceID = deviceID

	mockRepo.On("GetDeployment", ctx, deploymentID).Return(deployment, nil)
	mockRepo.On("GetBlock", ctx, configBlockID).Return(block, nil)
	mockRepo.On("UpdateDeployment", ctx, mock.AnythingOfType("*models.Deployment")).Return(nil)
	mockRepo.On("UpdateBlockStatus", ctx, configBlockID, models.ConfigStatusDeployed).Return(nil)
	mockAudit.On("LogConfigEvent", ctx, models.AuditEventConfigDeploy, deviceID, (*uuid.UUID)(nil), models.AuditResultSuccess, mock.Anything).Return(nil)

	err := manager.CompleteDeployment(ctx, deploymentID, true, "Deployed successfully")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestDiff(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	blockID1 := uuid.New()
	blockID2 := uuid.New()

	block1 := createTestBlock()
	block1.ID = blockID1
	block1.Content = "hostname router1\ninterface Gi0/0\n  ip address 10.0.0.1 255.255.255.0"

	block2 := createTestBlock()
	block2.ID = blockID2
	block2.Content = "hostname router1\ninterface Gi0/0\n  ip address 10.0.0.2 255.255.255.0"

	mockRepo.On("GetBlock", ctx, blockID1).Return(block1, nil)
	mockRepo.On("GetBlock", ctx, blockID2).Return(block2, nil)

	diff, err := manager.Diff(ctx, blockID1, blockID2)

	assert.NoError(t, err)
	assert.NotEmpty(t, diff)
	mockRepo.AssertExpectations(t)
}

// Benchmark tests
func BenchmarkCreateBlock(b *testing.B) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	deviceID := uuid.New()
	content := "hostname test-router\ninterface GigabitEthernet0/0\n  ip address 10.0.0.1 255.255.255.0"
	authorID := uuid.New()

	mockRepo.On("CreateBlock", ctx, mock.AnythingOfType("*models.ConfigBlock")).Return(nil)
	mockAudit.On("LogConfigEvent", ctx, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.CreateBlock(ctx, deviceID, content, &authorID)
	}
}

func BenchmarkValidateBlock(b *testing.B) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	manager := config.NewManager(mockRepo, mockAudit, logger)

	block := createTestBlock()

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)
	mockRepo.On("UpdateBlockStatus", ctx, block.ID, models.ConfigStatusValidated).Return(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.ValidateBlock(ctx, block.ID)
	}
}
