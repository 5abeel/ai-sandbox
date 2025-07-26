
import gymnasium as gym
import time
import matplotlib.pyplot as plt
import numpy as np

# Define bins for each observation variable
NUM_BINS = 6 # bins per state variable

# the values (-2.4, 2.4), (-3.0, 3.0), (-0.21, 0.21), (-3.0, 3.0) are the limits
# of the observation space for CartPole-v1 environment

position_bins = np.linspace(-2.4, 2.4, NUM_BINS) # CartPole's position limits
velocity_bins = np.linspace(-3.0, 3.0, NUM_BINS)
angle_bins = np.linspace(-0.21, 0.21, NUM_BINS) ## -12 degrees to 12 degrees (in radians -0.21 to 0.21)
angular_velocity_bins = np.linspace(-3.0, 3.0, NUM_BINS)

# Notes and explanation:
## np.linspace() will give us 6 edges (5 evenly spaced bins)
## (-2.4, 2.4, 6) will give us [-2.4, -1.44, -0.48, 0.48, 1.44, 2.4]
##                                |------|-----|-----|-----|-----|
##                        Bins:       0     1     2     3     4

# Convert continuous observation space into discrete indices
# We will use np.digitize() to find the index of the bin that each observation falls into
# For example, if the position observation is 0.5, it will fall into the bin
# [0.48, 1.44), which is the 4th bin (index 3 in Python)
# So, we will use np.digitize to convert the continuous observation space
# into discrete indices that correspond to the bins we defined above
def discretize_observation(obs):

    position, velocity, angle, angular_velocity = obs    
    state = (
        np.digitize(position, position_bins),
        np.digitize(velocity, velocity_bins),
        np.digitize(angle, angle_bins),
        np.digitize(angular_velocity, angular_velocity_bins)
    )
    return state # return the state (a tuple of 4 integers, one for each observation variable)

# Q-learning equation
# 
# Q(s, a) = Q(s, a) + α * (r + γ * max_a' Q(s', a') - Q(s, a))
# Q[state, action] = Q[state, action] + alpha * (reward + gamma * max(Q[next_state]) - Q[state, action])
#

# Q-learning parameters
alpha = 0.1  # Learning rate
gamma = 0.99 # Discount factor
epsilon = 1.0 # Exploration probability
epsilon_min = 0.01 # Minimum value for epsilon
epsilon_decay = 0.995 # Decay rate for epsilon

env = gym.make('CartPole-v1', render_mode='human')

# Init Q-learning table shape
# The Q-table will have dimensions based on the number of bins for each observation variable
# The last dimension corresponds to the number of actions (left or right)
# For CartPole-v1, the action space has 2 actions (0: push left, 1: push right)
# This Q-table takes 5-dimensional array for the 4 observation variables and 1 action variable
q_table = np.zeros((NUM_BINS + 1, NUM_BINS + 1, NUM_BINS + 1, NUM_BINS + 1, env.action_space.n))

episode_rewards = []
num_episodes = 500
max_steps = 500

for episode in range(num_episodes):
    obs, info = env.reset()
    state = discretize_observation(obs) # s in Q-learning equation
    total_reward = 0

    for _ in range(max_steps):
        # Epsilon-greedy action selection
        if np.random.rand() < epsilon:
            action = env.action_space.sample()  # Explore: select a random action
        else:
            action = np.argmax(q_table[state])  # Exploit: select the best action based on Q-table
        # action => a in Q-learning equation

        next_obs, reward, terminated, truncated, info = env.step(action)
        next_state = discretize_observation(next_obs) # s' in Q-learning equation

        # Update Q-table using the Q-learning equation
        best_next_action = np.argmax(q_table[next_state])  # a' in Q-learning equation
        td_target = reward + gamma * q_table[next_state][best_next_action]  # Q(s', a')
        td_error = td_target - q_table[state][action]  # difference between target and current Q-value, indicates how much the current Q-value needs to be updated
        q_table[state][action] += alpha * td_error  # Incremental Q-value update (alpha = learning rate (step-size), how much of new experience overrides old knowledge)

        state = next_state  # Move to the next state
        total_reward += reward

        if terminated or truncated:
            break
    
    episode_rewards.append(total_reward)
    # Reduce epsilon after each episode (more exploitation, less exploration)
    if epsilon > epsilon_min:
        epsilon *= epsilon_decay
    
    # Optional: print progress occasionally
    if (episode + 1) % 50 == 0:
        print(f"Episode {episode + 1}/{num_episodes}, Total Reward: {total_reward}, Epsilon: {epsilon:.4f}")

env.close()

plt.figure(figsize=(10,5))
plt.plot(np.arange(1, num_episodes + 1), episode_rewards, color='b', alpha=0.7)
plt.title('CartPole Q-learning: Episode Rewards Over Time')
plt.xlabel('Episode')
plt.ylabel('Total Reward')
plt.grid(True)
plt.savefig("cartpole_qlearning_rewards.png")
# plt.show() ## cannot be displayed in this env
print("Plot saved as cartpole_qlearning_rewards.png")

#
# Comments & Notes:
#   This may look like just a feedback loop with specific rules coded instead of ML, but there is a subtlety to it.
#   1. We do not program what the "right" action is.
#   2. Here, the agent learns from the environment with a blank Q-table and fills it with knowledge over time.
#   3. The rules define the learning, not behavior (we do not program "if pole falls left, do this action" etc)
#   4. Over time, agent's behavior changes as it learns.
#   5. If environment changes (modify physics, add noise etc), agent can relearn and adapt to the new environment,
#      (in classic algos, if world changes, code needs to change too).
#   6. This is the essence of reinforcement learning: learning from interaction with the environment.
#