---
layout: post
title: Adventures in DeepRacer
---

Recently, I decided I want to race cars. Luckily for me, [AWS DeepRacer](https://aws.amazon.com/deepracer/?did=ft_card&trk=ft_deepracer) will let me race cars with none of the usual risk to my wallet or personal health by using reinforcement learning to train my "driver" - a machine learning model.


## Deep Racing - Round One

For my first go round, I'm going to just click through the "quick start" and change nothing. While certainly not the most interesting, I need to have a baseline for comparison.

The default reward function, which is what determines the magnitude of reinforcement fed back into the model, is this:

```python
def reward_function(params):
    '''
    Example of rewarding the agent to follow center line
    '''
    
    # Read input parameters
    track_width = params['track_width']
    distance_from_center = params['distance_from_center']
    
    # Calculate 3 markers that are at varying distances away from the center line
    marker_1 = 0.1 * track_width
    marker_2 = 0.25 * track_width
    marker_3 = 0.5 * track_width
    
    # Give higher reward if the car is closer to center line and vice versa
    if distance_from_center <= marker_1:
        reward = 1.0
    elif distance_from_center <= marker_2:
        reward = 0.5
    elif distance_from_center <= marker_3:
        reward = 0.1
    else:
        reward = 1e-3  # likely crashed/ close to off track
    
    return float(reward)
```

I also turn the "Stop time", the maximum time training will occur, down to 15 minutes. I'll be suprised if it takes this long, but I'm trying to get the most out of the [ten hours of training in the free tier](https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc&awsf.Free%20Tier%20Types=tier%23trial&awsm.page-all-free-tier=1&awsf.Free%20Tier%20Categories=categories%23ai-ml&all-free-tier.q=deepracer&all-free-tier.q_operator=AND).


### Results

After waiting a few minutes for the model to initialize, I'm frankly blown away by this. Not by the model - my car hasn't made it past the first turn on the simple oval track, somewhat comically, but by the fact that I can view a simulated video of my "car" driving on the track. I have fond memories of playing with the early iterations of the Lego Mindstorm, and this felt like I was doing that again.

As previously noted, this model performed... not greatly. 



## Round Two - Hyperlearning

Since the last model clearly didn't learn how to drive fast enough, I'm going to alter the hyperparameters and reward function to create a much "stronger" reinforcement on results. I know that this isn't quite how it works, but what can go wrong?

Specifically, I'm going to bump up the learning rate by an order of magnitude - the default is 0.0003, and I'm going to set it to 0.001.

Additionally, I'm going to alter the reward function to do the following:
* Reward will decreate exponentially as the car departs center line, with being exactly on center line having a reward of over 9000 (I have jokes)
* Further, rewards will recieve an amplification based upon the direction of steering - for example, if the agent is left-of-center and also steering left, that's a paddlin'.
* Just for kicks, I'm also going to increase rewards in relation to speed - human drivers feel good going fast, robots deserve the same.

The reward function for the above:

```python
def reward_function(params):
    track_width = params['track_width']
    distance_from_center = params['distance_from_center']
    steering_angle = params['steering_angle']
    speed = params['speed']
    is_left_of_center = params['is_left_of_center']

    MAX_REWARD = 9001
    STEERING_COUNTERACT_MUL = 0.1
    SPEED_MUL = 10
    
    # Distance modifier
    reward = MAX_REWARD**(1/(max((distance_from_center, 1))))

    # Steering correction
    if (is_left_of_center and steering_angle < 0):
        reward = reward * STEERING_COUNTERACT_MUL
    elif (not is_left_of_center and steering_angle > 0):
        reward = reward * STEERING_COUNTERACT_MUL
    
    # Speed multiplier
    # gotta go fast, but only if we're near center and steering correctly
    if distance_from_center < 5
       and ((is_left_of_center and steering_angle > 0)
            or (not is_left_of_center and steering_angle < 0)
            or steering_angle = 0):
        reward = reward + (speed*SPEED_MUL)
    
    return float(reward)
```

### Results

This model definitely performed better than the last, and I'm now ranked in the 33rd percentile, while my first model was second to last - likely not helped by my extremely short training periods. Browsing through the top racers, I notice that they all seem to go much faster overall, and decelerate as soon as they detect a turn is needed.

## Round three - Full speed ahead

Let's try doing two things - reward speed expoentially, as well as reward slowing down when a turn becomes necessary. I'm also going to let this model train first for 15 minutes to see if it's looking like I'm having the results I want, and if it is I'll let it train for a full hour.

Reward function for my first session:
```python
def reward_function(params):
    track_width = params['track_width']
    distance_from_center = params['distance_from_center']
    steering_angle = params['steering_angle']
    speed = params['speed']
    is_left_of_center = params['is_left_of_center']

    REWARD_BASE = 3
    STEERING_COUNTERACT_MUL = 0.1
    SPEED_BASE = 7
    
    # Distance modifier
    reward = REWARD_BASE**( 1/(max((distance_from_center, 0.1))) )

    # Steering correction
    if (is_left_of_center and steering_angle < 0):
        reward = reward * STEERING_COUNTERACT_MUL
    elif (not is_left_of_center and steering_angle > 0):
        reward = reward * STEERING_COUNTERACT_MUL
    
    # Speed multiplier
    # gotta go fast, but only if we're near center and steering correctly
    if distance_from_center < track_width * 0.20:
        if ((is_left_of_center and steering_angle > 0)
             or (not is_left_of_center and steering_angle < 0)
             or steering_angle == 0):
            reward = reward + (SPEED_BASE**speed)
    else:
        # If we're far off center, we need to punish speed
        reward_loss = (SPEED_BASE/2)**speed

        # If we're turning wrong, we need to punish that
        if ((is_left_of_center and steering_angle < 0)
             or (not is_left_of_center and steering_angle > 0)):
            reward_loss += 3**abs(steering_angle)
        reward = reward - reward_loss

    return float(reward)
```

That model... went poorly. I'm going to try adjusting my reward to be based primarily on speed, with detractors and adders based on distance from center and steering.

```python
def reward_function(params):
    track_width = params['track_width']
    distance_from_center = params['distance_from_center']
    steering_angle = params['steering_angle']
    speed = params['speed']
    is_left_of_center = params['is_left_of_center']

    REWARD_BASE = 8
    SPEED_BASE = REWARD_BASE/2
    STEERING_COUNTERACT_BASE = 10
    ACCEPTABLE_DISTANCE = track_width * 0.1
    
    # Distance modifier
    reward = REWARD_BASE**speed

    # Steering correction
    if (is_left_of_center and steering_angle > 0 and distance_from_center > 0.1):
        reward = reward - steering_angle**min((distance_from_center, 3))
    elif (not is_left_of_center and steering_angle < 0 and distance_from_center > 0.1):
        reward = reward - steering_angle**min((distance_from_center, 3))
    
    # If we're far off center, we need to punish speed
    if distance_from_center > ACCEPTABLE_DISTANCE:
        modifier = (REWARD_BASE/1.5)**speed
        reward = reward - modifier

    # I have no earthly idea why I sometimes end up with an imaginary reward, but here this is
    if isinstance(reward, complex):
        reward = reward.real

    return float(reward)
```

### Results

This model went better, with a track time of 4 minutes and 30 seconds. With 54 "Off-track" events that cost three seconds each, 2 minutes and 42 seconds of that time is penalty time. As with any good "athlete," I reviewed the footage of my run and gleaned two insights:

* More often than not, off-track events were caused by my racer spinning out due to overcorrection.
* Somehow, we need to incentivise our race to slow down into corners.


## Conclusions

Unfortunately, I'm plenty busy between my real life and work, so that's about all I have time to do. It was an interesting excercise in building machine learning models nontheless, and it was super cool to see the training take place in a simulated real-time way. Overall, I'd encourage anyone with beginner level Python skills looking to start playing around with deep learning to play around with the free trial of DeepRacer.
