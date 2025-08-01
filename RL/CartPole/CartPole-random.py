# Simple RL agent - agent takes random actions

import gymnasium as gym
import time
import matplotlib.pyplot as plt

env = gym.make('CartPole-v1', render_mode='human')
episode_rewards = []

for episode in range(10): # Run 10 episodes
    observation, info = env.reset() # env.reset() returns observation, which is initial state (position, velocity etc.)
    total_reward = 0
    for _ in range(1000):
        action = env.action_space.sample()  # Random
        observation, reward, terminated, truncated, info = env.step(action)
        total_reward += reward
        if terminated or truncated:
            break
    episode_rewards.append(total_reward)
    print("Episode:", episode + 1, "Total reward:", total_reward)
    time.sleep(1)

env.close()

episodes = list(range(1, len(episode_rewards) + 1))

plt.figure(figsize=(10, 5))
plt.plot(episodes, episode_rewards, marker='o', linestyle='-', color='b')
plt.title('Episode Rewards Over Time')
plt.xlabel('Episode')
plt.ylabel('Total Reward')
plt.xticks(episodes)
plt.grid(True)
# plt.show() ## cannot be displayed in this env, save png in pwd instead
plt.savefig("rewards_plot.png")
