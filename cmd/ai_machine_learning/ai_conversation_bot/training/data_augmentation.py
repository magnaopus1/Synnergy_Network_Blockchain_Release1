import random
import re
import numpy as np
import pandas as pd
import logging
import yaml
from nltk.corpus import wordnet
from sklearn.utils import shuffle
from typing import List, Tuple

# Configuration
config_path = '/Users/admin/Desktop/synnergy_network/pkg/synnergy_network/core/ai_machine_learning/ai_conversation_bot/config/training_config.yaml'
with open(config_path, 'r') as file:
    config = yaml.safe_load(file)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Synonym replacement
def synonym_replacement(words: List[str], n: int) -> List[str]:
    new_words = words.copy()
    random_word_list = list(set([word for word in words if word not in stop_words]))
    random.shuffle(random_word_list)
    num_replaced = 0
    for random_word in random_word_list:
        synonyms = get_synonyms(random_word)
        if len(synonyms) >= 1:
            synonym = random.choice(list(synonyms))
            new_words = [synonym if word == random_word else word for word in new_words]
            num_replaced += 1
        if num_replaced >= n:
            break

    sentence = ' '.join(new_words)
    new_words = sentence.split(' ')

    return new_words

# Get synonyms
def get_synonyms(word: str) -> List[str]:
    synonyms = set()
    for syn in wordnet.synsets(word):
        for lemma in syn.lemmas():
            synonym = lemma.name().replace('_', ' ').replace('-', ' ').lower()
            synonym = "".join([char for char in synonym if char in ' qwertyuiopasdfghjklzxcvbnm'])
            synonyms.add(synonym)
    if word in synonyms:
        synonyms.remove(word)
    return list(synonyms)

# Random insertion
def random_insertion(words: List[str], n: int) -> List[str]:
    new_words = words.copy()
    for _ in range(n):
        add_word(new_words)
    return new_words

def add_word(new_words: List[str]):
    synonyms = []
    counter = 0
    while len(synonyms) < 1:
        random_word = new_words[random.randint(0, len(new_words)-1)]
        synonyms = get_synonyms(random_word)
        counter += 1
        if counter >= 10:
            return
    random_synonym = synonyms[random.randint(0, len(synonyms)-1)]
    random_idx = random.randint(0, len(new_words)-1)
    new_words.insert(random_idx, random_synonym)

# Random swap
def random_swap(words: List[str], n: int) -> List[str]:
    new_words = words.copy()
    for _ in range(n):
        new_words = swap_word(new_words)
    return new_words

def swap_word(new_words: List[str]) -> List[str]:
    random_idx_1 = random.randint(0, len(new_words)-1)
    random_idx_2 = random.randint(0, len(new_words)-1)
    new_words[random_idx_1], new_words[random_idx_2] = new_words[random_idx_2], new_words[random_idx_1]
    return new_words

# Random deletion
def random_deletion(words: List[str], p: float) -> List[str]:
    if len(words) == 1:
        return words

    new_words = []
    for word in words:
        r = random.uniform(0, 1)
        if r > p:
            new_words.append(word)

    if len(new_words) == 0:
        rand_int = random.randint(0, len(words)-1)
        return [words[rand_int]]

    return new_words

# Data Augmentation
def augment_sentence(sentence: str, alpha_sr: float, alpha_ri: float, alpha_rs: float, p_rd: float, num_aug: int) -> List[str]:
    words = sentence.split(' ')
    num_words = len(words)

    augmented_sentences = []
    num_new_per_technique = int(num_aug/4) + 1

    # Synonym replacement
    n_sr = max(1, int(alpha_sr*num_words))
    for _ in range(num_new_per_technique):
        a_words = synonym_replacement(words, n_sr)
        augmented_sentences.append(' '.join(a_words))

    # Random insertion
    n_ri = max(1, int(alpha_ri*num_words))
    for _ in range(num_new_per_technique):
        a_words = random_insertion(words, n_ri)
        augmented_sentences.append(' '.join(a_words))

    # Random swap
    n_rs = max(1, int(alpha_rs*num_words))
    for _ in range(num_new_per_technique):
        a_words = random_swap(words, n_rs)
        augmented_sentences.append(' '.join(a_words))

    # Random deletion
    for _ in range(num_new_per_technique):
        a_words = random_deletion(words, p_rd)
        augmented_sentences.append(' '.join(a_words))

    augmented_sentences = shuffle(augmented_sentences)

    augmented_sentences = augmented_sentences[:num_aug]

    return augmented_sentences

# Load data
def load_data(file_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    df = pd.read_csv(file_path)
    return df['text'].tolist(), df['label'].tolist()

# Save augmented data
def save_data(data: List[Tuple[str, int]], file_path: str):
    df = pd.DataFrame(data, columns=['text', 'label'])
    df.to_csv(file_path, index=False)

# Augment data
def augment_data(input_file: str, output_file: str, alpha_sr: float, alpha_ri: float, alpha_rs: float, p_rd: float, num_aug: int):
    sentences, labels = load_data(input_file)
    augmented_data = []

    for sentence, label in zip(sentences, labels):
        augmented_sentences = augment_sentence(sentence, alpha_sr, alpha_ri, alpha_rs, p_rd, num_aug)
        augmented_data.extend([(aug_sentence, label) for aug_sentence in augmented_sentences])

    save_data(augmented_data, output_file)

# Main Function
def main():
    augment_data(
        input_file=config['data']['training_data_path'],
        output_file=config['data']['augmented_data_path'],
        alpha_sr=config['augmentation']['alpha_sr'],
        alpha_ri=config['augmentation']['alpha_ri'],
        alpha_rs=config['augmentation']['alpha_rs'],
        p_rd=config['augmentation']['p_rd'],
        num_aug=config['augmentation']['num_aug']
    )

if __name__ == '__main__':
    main()
