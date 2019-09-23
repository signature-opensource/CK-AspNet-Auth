using CodeCake.Abstractions;

namespace CodeCake
{
    public abstract class NPMCIWorkflow : ICIWorkflow
    {
        /// <summary>
        /// Because the clean is made by a npm script, we must install dependencies before cleaning.
        /// </summary>
        public void Clean()
        {
            RunNpmCI();
            RunClean();
        }

        protected abstract void RunNpmCI();

        protected abstract void RunClean();

        public abstract void Build();

        public abstract void Test();
    }
}
