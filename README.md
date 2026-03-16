# AI Detection System for Mobile Network Security

This project implements comparative analysis of CNN and RNN models for detecting false base station attacks in mobile network signaling data.

## Project Structure

```
ai-detection/
├── models/          # Trained models (CNN and RNN)
├── data/            # Preprocessed datasets
├── notebooks/       # Jupyter notebooks for analysis
├── results/         # Performance metrics and comparisons
├── scripts/         # Training and evaluation scripts
└── README.md
```

## Models Implemented

### Convolutional Neural Network (CNN)
- Architecture: 1D CNN with multiple convolutional layers
- Input: Sliding window sequences of cellular signaling features
- Output: Binary classification (attack/normal)

### Recurrent Neural Network (RNN)
- Architecture: LSTM-based RNN for sequence processing
- Input: Temporal sequences of network signaling data
- Output: Binary classification with temporal context

## Dataset

The models are trained on the same dataset used in the MOBI-Detector project:
- **Normal data**: Legitimate cellular network signaling
- **Attack data**: Various false base station attack patterns
- **Features**: 1544 cellular signaling parameters
- **Sliding windows**: 20-time step sequences

## Performance Metrics

- Accuracy
- Precision
- Recall
- F1-Score
- Confusion Matrix
- ROC-AUC

## Usage

1. **Data Preparation**: Run `notebooks/data_preparation.ipynb`
2. **Model Training**: Run `notebooks/cnn_training.ipynb` and `notebooks/rnn_training.ipynb`
3. **Evaluation**: Run `notebooks/model_comparison.ipynb`
4. **Results**: View comparative analysis in `results/`

## Dependencies

- PyTorch
- scikit-learn
- pandas
- numpy
- matplotlib
- seaborn
- jupyter