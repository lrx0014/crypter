pipeline {
  agent {
    dockerfile {
      filename 'build.Dockerfile'
    }

  }
  stages {
    stage('test') {
      steps {
        sh 'echo "test"'
      }
    }

  }
}